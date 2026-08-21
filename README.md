# Zwarden

Extension navigateur de gestion de mots de passe, open source, compatible
[Vaultwarden](https://github.com/dani-garcia/vaultwarden) et l'API Bitwarden.

Objectif : la même compatibilité, un ordre de grandeur en moins de poids.

## Pourquoi

L'extension Bitwarden officielle (2026.7.0) mesurée sur disque :

| Poste | Taille | Conséquence |
|---|---|---|
| `background.js` | 3,3 Mo | service worker MV3 tué après 30 s d'inactivité → 3,3 Mo reparsés à chaque réveil |
| `bitwarden_wasm_internal.wasm` | 7,4 Mo | chargé au démarrage, et présent en double dans le paquet |
| `bootstrap-autofill-overlay.js` | 1,7 Mo | injecté dans **chaque frame** de **chaque page** visitée |
| popup Angular | ~2 Mo | plusieurs centaines de ms avant le premier rendu |

Zwarden vise **< 300 Ko** au total.

Les leviers, dans l'ordre d'impact :

1. **WebCrypto natif** plutôt qu'un SDK Rust compilé en WASM. AES-256-CBC,
   HMAC-SHA256, PBKDF2-SHA256 et SHA-2 sont déjà dans le navigateur : natifs,
   à temps constant, audités, et 0 octet de bundle. Seul Argon2id nécessite du
   WASM (~45 Ko), chargé en import dynamique et uniquement au déverrouillage
   d'un compte configuré ainsi.
2. **Autofill en deux étages** : un détecteur de formulaire léger à
   `document_start`, le moteur d'autofill injecté seulement quand un champ
   pertinent est détecté.
3. **Preact** (~10 Ko de runtime) au lieu d'Angular.
4. **Service worker mince** : logique lourde en modules dynamiques, état
   volatil en `chrome.storage.session`.

## État

Le noyau cryptographique est implémenté et testé. Le reste est en cours.

- [x] Encodage (base64, UTF-8, comparaison à temps constant)
- [x] `EncString` — analyse et sérialisation des 7 types Bitwarden
- [x] `SymmetricCryptoKey` — clés 32/64 octets
- [x] AES-256-CBC + HMAC-SHA256, Encrypt-then-MAC
- [x] Dérivation de clé : PBKDF2-SHA256 et Argon2id
- [x] 106 tests, dont les vecteurs RFC 4231 / 5869 / 7914
- [ ] Client API Vaultwarden
- [ ] Service worker et cycle de vie du verrouillage
- [ ] Popup (déverrouillage, liste, recherche, copie)
- [ ] TOTP et générateur de mots de passe
- [ ] Création / édition d'items
- [ ] Autofill

## Modèle de sécurité

Le serveur est traité comme **non fiable**. Il ne voit jamais ni le mot de passe
maître, ni la clé maître, ni aucun contenu en clair.

Décisions notables, dont certaines sont plus strictes que Bitwarden :

- **MAC vérifié avant tout déchiffrement.** Le ciphertext ne touche jamais AES
  si le HMAC ne correspond pas — c'est ce qui ferme les oracles de padding sur
  CBC. La comparaison est à temps constant.
- **Refus des rétrogradations.** Une donnée de type 2 (authentifiée) présentée
  comme type 0 (non authentifiée) est rejetée. Sans cela, un serveur hostile
  peut dépouiller le MAC et retrouver un oracle de padding.
- **Écriture toujours authentifiée.** Chiffrer avec une clé sans `macKey` lève
  une erreur. Le type 0 reste lisible pour la migration d'anciens coffres.
- **Paramètres KDF validés.** `iterations` et `memory` viennent du serveur
  *avant* authentification : un serveur compromis peut annoncer 1 itération pour
  rendre la clé maître triviale à casser hors ligne. Zwarden rejette les
  configurations en dessous du plancher OWASP. Bitwarden ne fait pas cette
  vérification.
- **AES-128 (type 1) refusé** en déchiffrement : ré-chiffrement requis.

## Compatibilité

Format de chiffrement identique à Bitwarden, donc les coffres sont
interopérables dans les deux sens :

```
2.<iv b64>|<ciphertext b64>|<mac b64>
```

- clé maître : `PBKDF2-SHA256(mdp, e-mail normalisé, n)` ou `Argon2id(mdp, SHA-256(e-mail))`
- clé étirée : `HKDF-Expand(clé maître, "enc"|"mac")` — Expand seul, sans Extract
- hash serveur : `PBKDF2-SHA256(clé maître, mdp, 1 itération)`

## Développement

```bash
npm install
npm test          # 106 tests
npm run typecheck # TypeScript strict
npm run build
```

## Documentation

- [`docs/CRYPTO.md`](docs/CRYPTO.md) — modèle de menace, hiérarchie des clés,
  schéma de chiffrement, durcissements et leurs justifications.

## Licence

AGPL-3.0-only.
