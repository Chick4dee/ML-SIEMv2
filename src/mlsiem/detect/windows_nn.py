"""Нейросеть окон: компактный двунаправленный GRU на последовательности потоков окна
(фича 007, research R4, R5).

Почему такая архитектура. Окон мало (train ≈14.5 тыс., ×4 с аугментацией), поэтому модель
намеренно маленькая (~150 тыс. параметров): большая выучила бы train наизусть. Урок v1
(CNN+LSTM, macro PR-AUC 0.443): начинать с малой модели и честного сравнения с бустингом.

    поток (62 канала) → линейная проекция 64 → ReLU → biGRU(96) по потокам окна
    → маскированные mean и max по времени (паддинг не участвует)
    → склейка с 4 скалярами окна (размер окна, усечено, число целей и портов)
    → MLP 388 → 128 → классы (dropout 0.2)

Скаляры нужны, чтобы нейросеть знала размер окна и после усечения до 128 потоков —
иначе она проигрывала бы бустингу просто потому, что «не видит» половину скана.

PyTorch — необязательная зависимость (группа `nn`): модуль импортирует `torch` только внутри
функций, так что цепочка и быстрые тесты работают и без него. Нет PyTorch — понятное
сообщение «установите `uv sync --extra nn`», а не голый ImportError.

Ранняя остановка — по отложенному хвосту train, а не по val (R5): val остаётся для выбора
победителя и порога наравне с бустингом. Иначе у нейросети было бы нечестное преимущество
подгонки под val.
"""

from __future__ import annotations

import copy
import logging
import os
import time
from dataclasses import dataclass, field
from typing import Any

import numpy as np

log = logging.getLogger("mlsiem")

INSTALL_HINT = "установите PyTorch: `uv sync --extra nn` (или запустите эксперимент с --skip-nn)"
N_SCALARS = 4
HEAD_HIDDEN = 128
# Значение «минус бесконечность» для max-пулинга по паддингу: в половинной точности (AMP)
# настоящий −inf превращает градиенты в NaN, а −1e4 заведомо меньше любых активаций GRU
NEG = -1.0e4


class NNUnavailable(RuntimeError):
    """PyTorch не установлен или нет запрошенного устройства."""


def require_torch():
    """`torch` или понятная ошибка. Детерминированный cuBLAS требует переменной окружения
    ДО первой операции на видеокарте — ставим её здесь, пока CUDA не инициализирована."""
    os.environ.setdefault("CUBLAS_WORKSPACE_CONFIG", ":4096:8")
    try:
        import torch
    except ImportError as exc:
        raise NNUnavailable(f"нет PyTorch — {INSTALL_HINT}") from exc
    return torch


def torch_available() -> bool:
    try:
        require_torch()
    except NNUnavailable:
        return False
    return True


def resolve_device(name: str) -> str:
    """`auto` → `cuda`, если PyTorch видит видеокарту, иначе `cpu`; `cuda` без видеокарты —
    ошибка (владелец просил именно её); `cpu` — всегда."""
    if name not in ("auto", "cuda", "cpu"):
        raise ValueError(f"--device: ожидалось auto, cuda или cpu, а передано {name!r}")
    if name == "cpu":
        return "cpu"
    torch = require_torch()
    if torch.cuda.is_available():
        return "cuda"
    if name == "cuda":
        raise NNUnavailable("запрошена видеокарта (--device cuda), но PyTorch её не видит")
    return "cpu"


def device_title(device: str) -> str:
    """Как устройство называется в карточке и отчёте: `cuda:0 <имя карты>` или `cpu`."""
    if device == "cuda":
        torch = require_torch()
        return f"cuda:0 {torch.cuda.get_device_name(0)}"
    return "cpu"


_MODEL_CLASS = None


def _model_class():
    """Класс модели строится лениво: `nn.Module` нельзя объявить без импорта torch."""
    global _MODEL_CLASS
    if _MODEL_CLASS is not None:
        return _MODEL_CLASS
    torch = require_torch()
    from torch import nn
    from torch.nn.utils.rnn import pack_padded_sequence, pad_packed_sequence

    class WindowGRU(nn.Module):
        def __init__(self, n_in, n_classes, proj, hidden, dropout, n_scalars=N_SCALARS):
            super().__init__()
            self.proj = nn.Linear(n_in, proj)
            self.gru = nn.GRU(proj, hidden, num_layers=1, batch_first=True, bidirectional=True)
            width = 2 * 2 * hidden + n_scalars  # (mean + max) × два направления + скаляры
            self.head = nn.Sequential(
                nn.Dropout(dropout),
                nn.Linear(width, HEAD_HIDDEN),
                nn.ReLU(),
                nn.Dropout(dropout),
                nn.Linear(HEAD_HIDDEN, n_classes),
            )

        def forward(self, x, mask, scalars):
            h = torch.relu(self.proj(x))
            # Упакованная последовательность: GRU вообще не видит шагов паддинга, поэтому
            # выход не зависит от того, что лежит в хвосте тензора (проверяется тестом)
            lengths = mask.sum(dim=1).clamp(min=1).to("cpu")
            packed = pack_padded_sequence(h, lengths, batch_first=True, enforce_sorted=False)
            out, _ = self.gru(packed)
            out, _ = pad_packed_sequence(out, batch_first=True, total_length=x.shape[1])
            m = mask.unsqueeze(-1)
            mf = m.to(out.dtype)
            mean = (out * mf).sum(dim=1) / mf.sum(dim=1).clamp(min=1)
            mx = out.masked_fill(~m, NEG).max(dim=1).values
            return self.head(torch.cat([mean, mx, scalars.to(out.dtype)], dim=1))

    _MODEL_CLASS = WindowGRU
    return WindowGRU


def build_gru(n_in: int, n_classes: int, params: dict[str, Any]):
    return _model_class()(
        n_in, n_classes, int(params["proj"]), int(params["hidden"]), float(params["dropout"])
    )


def n_parameters(model) -> int:
    return int(sum(p.numel() for p in model.parameters()))


@dataclass
class SeqData:
    """Последовательности части: тензор, маска, скаляры и (для обучения) индексы классов."""

    X: np.ndarray
    mask: np.ndarray
    scalars: np.ndarray
    y: np.ndarray | None = None

    def __len__(self) -> int:
        return len(self.X)

    def take(self, idx: np.ndarray) -> SeqData:
        return SeqData(
            self.X[idx], self.mask[idx], self.scalars[idx], None if self.y is None else self.y[idx]
        )


@dataclass
class TrainHistory:
    epochs: int = 0
    best_epoch: int = 0
    best_holdout_loss: float | None = None
    train_loss: list[float] = field(default_factory=list)
    holdout_loss: list[float] = field(default_factory=list)
    seconds: float = 0.0
    peak_vram_mb: float | None = None


def class_weights(y: np.ndarray, n_classes: int, cap: float) -> np.ndarray:
    """Веса balanced (n / (k · n_c)) с потолком `cap`: иначе класс из пары окон получил бы
    вес в тысячи и раскачивал обучение (R5)."""
    counts = np.bincount(np.asarray(y), minlength=n_classes).astype(np.float64)
    present = counts > 0
    w = np.zeros(n_classes)
    w[present] = counts.sum() / (present.sum() * counts[present])
    return np.minimum(w, cap)


def _batches(n: int, size: int, order: np.ndarray | None = None):
    idx = np.arange(n) if order is None else order
    for lo in range(0, n, size):
        yield idx[lo : lo + size]


def _to_device(torch, data: SeqData, idx: np.ndarray, device: str):
    x = torch.from_numpy(np.ascontiguousarray(data.X[idx])).to(device, non_blocking=True)
    m = torch.from_numpy(np.ascontiguousarray(data.mask[idx])).to(device, non_blocking=True)
    s = torch.from_numpy(np.ascontiguousarray(data.scalars[idx])).to(device, non_blocking=True)
    return x, m, s


def _holdout_loss(torch, model, data: SeqData, device: str, batch: int, amp: bool) -> float:
    """Средняя кросс-энтропия на хвосте train — без весов классов, как logloss LightGBM на
    его eval-наборе: одинаковый критерий остановки у обоих участников."""
    model.eval()
    total, n = 0.0, 0
    loss_fn = torch.nn.CrossEntropyLoss(reduction="sum")
    with torch.no_grad():
        for idx in _batches(len(data), batch):
            x, m, s = _to_device(torch, data, idx, device)
            y = torch.from_numpy(data.y[idx]).to(device)
            with torch.autocast(device_type="cuda", dtype=torch.float16, enabled=amp):
                logits = model(x, m, s)
            total += float(loss_fn(logits.float(), y))
            n += len(idx)
    return total / max(n, 1)


def train_gru(
    fit: SeqData,
    holdout: SeqData | None,
    n_classes: int,
    params: dict[str, Any],
    *,
    seed: int,
    device: str,
):
    """Обучает GRU; возвращает (модель на CPU с лучшими весами, история обучения).

    AdamW, взвешенная кросс-энтропия (balanced с потолком), батчи из перемешанного train,
    смешанная точность только на CUDA, ранняя остановка по потере на хвосте train с
    терпением `patience`. Сид фиксирует и инициализацию, и порядок батчей.
    """
    torch = require_torch()
    torch.manual_seed(seed)
    np.random.seed(seed)
    torch.use_deterministic_algorithms(True, warn_only=True)
    if device == "cuda":
        torch.backends.cudnn.benchmark = False
        torch.cuda.reset_peak_memory_stats()
    amp = bool(params.get("amp", True)) and device == "cuda"
    batch = int(params["batch"])
    model = build_gru(fit.X.shape[2], n_classes, params).to(device)
    weights = torch.tensor(
        class_weights(fit.y, n_classes, float(params["class_weight_cap"])), dtype=torch.float32
    ).to(device)
    loss_fn = torch.nn.CrossEntropyLoss(weight=weights)
    opt = torch.optim.AdamW(
        model.parameters(), lr=float(params["lr"]), weight_decay=float(params["weight_decay"])
    )
    scaler = torch.amp.GradScaler("cuda", enabled=amp)
    rng = np.random.default_rng(seed)
    hist = TrainHistory()
    best_state = copy.deepcopy(model.state_dict())
    best = np.inf
    bad = 0
    started = time.perf_counter()
    for epoch in range(1, int(params["max_epochs"]) + 1):
        model.train()
        order = rng.permutation(len(fit))
        total, n = 0.0, 0
        for idx in _batches(len(fit), batch, order):
            x, m, s = _to_device(torch, fit, idx, device)
            y = torch.from_numpy(fit.y[idx]).to(device)
            opt.zero_grad(set_to_none=True)
            with torch.autocast(device_type="cuda", dtype=torch.float16, enabled=amp):
                logits = model(x, m, s)
            loss = loss_fn(logits.float(), y)
            scaler.scale(loss).backward()
            scaler.step(opt)
            scaler.update()
            total += float(loss.detach()) * len(idx)
            n += len(idx)
        hist.train_loss.append(total / max(n, 1))
        hist.epochs = epoch
        if holdout is None or len(holdout) == 0:
            # Хвоста нет (крошечные данные тестов) — обучаем все эпохи, лучшая = последняя
            best_state = copy.deepcopy(model.state_dict())
            hist.best_epoch = epoch
            continue
        h = _holdout_loss(torch, model, holdout, device, batch, amp)
        hist.holdout_loss.append(h)
        log.info("  GRU эпоха %d: потеря train %.4f, хвост %.4f", epoch, hist.train_loss[-1], h)
        if h < best - 1e-6:
            best, bad = h, 0
            best_state = copy.deepcopy(model.state_dict())
            hist.best_epoch, hist.best_holdout_loss = epoch, h
        else:
            bad += 1
            if bad >= int(params["patience"]):
                log.info("  ранняя остановка: %d эпох без улучшения на хвосте train", bad)
                break
    hist.seconds = time.perf_counter() - started
    if device == "cuda":
        hist.peak_vram_mb = torch.cuda.max_memory_allocated() / 2**20
    model.load_state_dict(best_state)
    return model.to("cpu").eval(), hist


def predict_gru(model, data: SeqData, *, device: str = "cpu", batch: int = 1024) -> np.ndarray:
    """Вероятности классов (softmax) батчами; float64 [n, классы]."""
    torch = require_torch()
    model = model.to(device).eval()
    out = []
    with torch.no_grad():
        for idx in _batches(len(data), batch):
            x, m, s = _to_device(torch, data, idx, device)
            out.append(torch.softmax(model(x, m, s).float(), dim=1).cpu().numpy())
    model.to("cpu")
    if not out:
        return np.zeros((0, model.head[-1].out_features))
    return np.vstack(out).astype(np.float64)


def save_state(model, path) -> None:
    torch = require_torch()
    torch.save(model.state_dict(), path)


def load_state(path, n_in: int, n_classes: int, params: dict[str, Any]):
    torch = require_torch()
    model = build_gru(n_in, n_classes, params)
    state = torch.load(path, map_location="cpu", weights_only=True)
    model.load_state_dict(state)
    return model.eval()
