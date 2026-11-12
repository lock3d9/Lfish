"use strict";

let language = "ru";
let catalog = {};
const localeNames = {ru: "ru-RU", en: "en-US", uk: "uk-UA"};

async function loadTranslations() {
  const response = await fetch("./i18n.json");
  if (!response.ok) throw new Error("Could not load interface translations");
  catalog = await response.json();
}

function t(source, values = {}) {
  const pair = catalog[source];
  const translated = (language === "en" ? pair?.[0] : language === "uk" ? pair?.[1] : source) ?? source;
  return translated.replace(/\{(\w+)\}/g, (match, key) => values[key] ?? match);
}

function translateMessage(source) {
  if (language === "ru" || !source) return source;
  if (Object.hasOwn(catalog, source)) return t(source);
  const newline = source.split("\n");
  if (newline.length > 1) return newline.map(translateMessage).join("\n");
  const colon = source.indexOf(": ");
  if (colon > 0) {
    const prefix = source.slice(0, colon);
    if (Object.hasOwn(catalog, prefix)) return t(prefix) + ": " + translateMessage(source.slice(colon + 2));
  }
  const sentence = source.split(". ");
  if (sentence.length === 2 && sentence.every(part => Object.hasOwn(catalog, part))) {
    return sentence.map(part => t(part)).join(". ");
  }
  return source;
}

function translateStatic() {
  document.documentElement.lang = language;
  document.querySelectorAll("[data-i18n]").forEach(el => { el.textContent = t(el.dataset.i18n); });
  for (const attr of ["aria-label", "title", "placeholder"]) {
    document.querySelectorAll(`[data-i18n-${attr}]`).forEach(el => {
      el.setAttribute(attr, t(el.getAttribute(`data-i18n-${attr}`)));
    });
  }
}
