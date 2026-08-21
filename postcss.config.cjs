// Configuration PostCSS vide, volontairement présente.
//
// Sans elle, Vite/Vitest fait remonter la recherche de configuration jusqu'à
// la racine du volume et peut charger un fichier étranger au projet (cas
// rencontré : un `.postcssrc.js` à la racine de D:\ cassait `npm test`).
// Ce fichier borne la recherche au projet.
module.exports = { plugins: [] };
