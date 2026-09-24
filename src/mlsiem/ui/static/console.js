/*
 * Скрипт консоли SOC. Маленький и без inline-кода: CSP страницы (default-src 'self')
 * разрешает только файлы с нашего адреса, поэтому все обработчики вешаются здесь,
 * по data-атрибутам и событиям htmx.
 *
 * Что он делает:
 * 1. Полоса «данные могут быть устаревшими» (FR-025): включается, когда опрос не достучался
 *    до сервера или сервер ответил 5xx; снимается первым успешным ответом. Ошибки 4xx от
 *    форм — это нормальные ответы («нужна резолюция», «конфликт»), их показывает сама форма.
 * 2. CSRF-заголовок для запросов htmx — дублирует hx-headers на <body> (research R7).
 * 3. Диалоги-вопросы (подтверждение действия, «вы не ответственный»): сервер присылает
 *    <dialog open data-modal>; без JS он виден прямо на странице, с JS — открывается модально.
 * 4. Автоотправка выбора прогона в шапке.
 *
 * Ответ 204 на опрос htmx 2 не вставляет в страницу (responseHandling в <meta htmx-config>),
 * поэтому прокрутка, раскрытые <details> и введённый текст при «ничего не изменилось»
 * не трогаются.
 */
(function () {
  "use strict";

  function staleBar(on) {
    var bar = document.getElementById("stale-bar");
    if (bar) {
      bar.hidden = !on;
    }
  }

  document.addEventListener("htmx:sendError", function () {
    staleBar(true);
  });

  document.addEventListener("htmx:responseError", function (e) {
    var status = e.detail && e.detail.xhr ? e.detail.xhr.status : 0;
    if (status === 0 || status >= 500) {
      staleBar(true);
    }
  });

  document.addEventListener("htmx:afterRequest", function (e) {
    var xhr = e.detail && e.detail.xhr;
    if (xhr && xhr.status > 0 && xhr.status < 500) {
      staleBar(false);
    }
  });

  document.addEventListener("htmx:configRequest", function (e) {
    var token = document.body && document.body.dataset.csrf;
    if (token && !e.detail.headers["X-CSRF-Token"]) {
      e.detail.headers["X-CSRF-Token"] = token;
    }
  });

  function openDialogs(root) {
    var scope = root && root.querySelectorAll ? root : document;
    var dialogs = scope.querySelectorAll("dialog[data-modal]");
    Array.prototype.forEach.call(dialogs, function (d) {
      if (d.dataset.shown || typeof d.showModal !== "function") {
        return;
      }
      d.dataset.shown = "1";
      // Сервер присылает open (чтобы было видно и без JS); модальный режим требует
      // сначала закрыть немодальный диалог
      if (d.open) {
        d.close();
      }
      d.showModal();
    });
  }

  document.addEventListener("htmx:afterSwap", function (e) {
    // после outerHTML-обмена target уже вне документа — ищем по всей странице
    openDialogs(document);
  });

  document.addEventListener("DOMContentLoaded", function () {
    openDialogs(document);
  });

  document.addEventListener("change", function (e) {
    var el = e.target;
    if (el && el.matches && el.matches("[data-autosubmit]") && el.form) {
      el.form.submit();
    }
  });
})();
