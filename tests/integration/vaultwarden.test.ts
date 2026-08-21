/**
 * @file Validation d'interopérabilité contre une vraie instance Vaultwarden.
 *
 * ## Pourquoi ce test existe
 *
 * Les tests unitaires prouvent la conformité aux RFC et la cohérence interne.
 * Ils ne prouvent **pas** qu'un coffre réel s'ouvre : la chaîne complète
 * (paramètres KDF du serveur → clé maître → clé étirée → clé du coffre →
 * champs des items) ne peut être validée que de bout en bout. C'est le seul
 * test capable de détecter une divergence de normalisation, de sel ou d'ordre
 * de dérivation.
 *
 * ## Exécution
 *
 * Ignoré par défaut. Nécessite un compte **jetable**, jamais un compte réel :
 *
 * ```bash
 * export ZWARDEN_TEST_SERVER=https://vault.exemple.fr
 * export ZWARDEN_TEST_EMAIL=compte+test@exemple.fr
 * export ZWARDEN_TEST_PASSWORD='...'
 * npx vitest run tests/integration
 * ```
 *
 * ## Discipline sur les secrets
 *
 * Aucun secret n'est écrit sur disque ni journalisé. Les assertions portent sur
 * des propriétés structurelles (longueurs, préfixes de type, nombre d'items) et
 * jamais sur des valeurs déchiffrées. Le rapport affiché est volontairement
 * expurgé.
 */

import { beforeAll, describe, expect, it } from 'vitest';

import { ApiClient, type LoginResult } from '../../src/core/api/apiClient.js';
import { EncString } from '../../src/core/crypto/encString.js';
import { SymmetricCryptoKey } from '../../src/core/crypto/symmetricCryptoKey.js';
import {
  decryptBytes,
  decryptStringOrNull,
  encryptString,
} from '../../src/core/crypto/cryptoService.js';
import {
  KdfType,
  type KdfConfig,
  deriveMasterKey,
  stretchMasterKey,
} from '../../src/core/crypto/kdf.js';

const SERVER = process.env['ZWARDEN_TEST_SERVER'];
const EMAIL = process.env['ZWARDEN_TEST_EMAIL'];
const PASSWORD = process.env['ZWARDEN_TEST_PASSWORD'];

const configured = Boolean(SERVER && EMAIL && PASSWORD);

/** Décrit un KDF sans révéler d'information sensible. */
function describeKdf(config: KdfConfig): string {
  return config.type === KdfType.PBKDF2_SHA256
    ? `PBKDF2-SHA256, ${config.iterations.toLocaleString('fr-FR')} itérations`
    : `Argon2id, t=${config.iterations} m=${config.memoryMiB}MiB p=${config.parallelism}`;
}

describe.skipIf(!configured)('interopérabilité Vaultwarden', () => {
  let client: ApiClient;
  let kdfConfig: KdfConfig;
  let masterKey: SymmetricCryptoKey;
  let session: LoginResult;
  let userKey: SymmetricCryptoKey;

  beforeAll(() => {
    client = new ApiClient({
      serverUrl: SERVER!,
      deviceIdentifier: '00000000-0000-4000-8000-00000000dead',
      deviceName: 'zwarden-interop-test',
    });
  });

  it('récupère les paramètres KDF via prelogin', async () => {
    kdfConfig = await client.prelogin(EMAIL!);

    expect(kdfConfig.iterations).toBeGreaterThan(0);
    console.log(`  KDF annoncé : ${describeKdf(kdfConfig)}`);
  });

  it('dérive une clé maître de 32 octets', async () => {
    masterKey = await deriveMasterKey(PASSWORD!, EMAIL!, kdfConfig);

    expect(masterKey.key).toHaveLength(32);
    expect(masterKey.isAuthenticated).toBe(false);
  });

  it("s'authentifie et reçoit la clé de coffre enveloppée", async () => {
    session = await client.login(EMAIL!, masterKey, PASSWORD!);

    expect(session.accessToken.length).toBeGreaterThan(0);
    expect(session.protectedUserKey).toBeDefined();

    // Le serveur a validé notre hash : la dérivation de la clé maître est
    // donc identique à celle du client officiel. C'est la première preuve
    // d'interopérabilité.
    console.log('  Authentification acceptée par le serveur');
  });

  it('déchiffre la clé du coffre avec la clé maître étirée', async () => {
    const stretched = await stretchMasterKey(masterKey);
    expect(stretched.key).toHaveLength(64);

    const wrapped = EncString.parse(session.protectedUserKey!);
    console.log(`  Clé de coffre enveloppée en type ${wrapped.encryptionType}`);

    // Preuve décisive : si HKDF-Expand, l'ordre enc/mac ou le format
    // divergeaient, la vérification du MAC échouerait ici.
    const raw = await decryptBytes(wrapped, stretched);
    userKey = new SymmetricCryptoKey(raw);

    expect(userKey.key).toHaveLength(64);
    expect(userKey.isAuthenticated).toBe(true);
    console.log('  Clé de coffre déchiffrée : 64 octets, authentifiée');
  });

  it('effectue un aller-retour complet en écriture puis lecture', async () => {
    // Preuve la plus forte d'interopérabilité : on chiffre localement, on
    // pousse au serveur, on resynchronise, et on redéchiffre. Si le format
    // divergeait sur un seul point, l'un des deux bouts échouerait.
    //
    // Les valeurs sont générées aléatoirement pour éviter toute collision avec
    // un contenu réel, et l'item est supprimé en fin de test.
    const marqueur = `zwarden-interop-${crypto.randomUUID()}`;
    const motDePasse = crypto.randomUUID();

    const corps = {
      type: 1,
      name: (await encryptString(marqueur, userKey)).toString(),
      notes: (await encryptString('Item de test Zwarden, supprimé automatiquement.', userKey))
        .toString(),
      login: {
        username: (await encryptString('utilisateur@test.local', userKey)).toString(),
        password: (await encryptString(motDePasse, userKey)).toString(),
        uris: [{ uri: (await encryptString('https://test.local', userKey)).toString(), match: null }],
      },
      favorite: false,
      folderId: null,
      organizationId: null,
      reprompt: 0,
      fields: [],
      passwordHistory: [],
    };

    const créé = await client.createCipher(session.accessToken, corps);
    expect(créé.id).toBeTruthy();
    console.log(`  Item créé côté serveur : ${créé.id}`);

    try {
      // Relecture par une synchronisation complète, pas depuis la réponse de
      // création : on veut valider le trajet aller-retour réel.
      const sync = await client.sync(session.accessToken);
      const relu = (sync.ciphers ?? []).find((c) => c.id === créé.id);
      expect(relu).toBeDefined();

      let itemKey = userKey;
      if (relu!.key) {
        itemKey = new SymmetricCryptoKey(await decryptBytes(EncString.parse(relu!.key), userKey));
      }

      const nom = await decryptStringOrNull(relu!.name, itemKey);
      const utilisateur = await decryptStringOrNull(relu!.login?.username, itemKey);
      const motDePasseRelu = await decryptStringOrNull(relu!.login?.password, itemKey);

      expect(nom).toBe(marqueur);
      expect(utilisateur).toBe('utilisateur@test.local');
      expect(motDePasseRelu).toBe(motDePasse);

      console.log('  Aller-retour validé : nom, utilisateur et mot de passe identiques');
    } finally {
      // Nettoyage systématique, y compris si une assertion a échoué.
      await client.deleteCipher(session.accessToken, créé.id);
      console.log('  Item de test supprimé');
    }
  });

  it('déchiffre les items existants du coffre', async () => {
    const sync = await client.sync(session.accessToken);
    const ciphers = sync.ciphers ?? [];

    console.log(`  ${ciphers.length} item(s) préexistant(s)`);

    // Un coffre vide est une condition d'environnement, pas un défaut du code.
    // L'aller-retour ci-dessus couvre déjà le chemin complet.
    if (ciphers.length === 0) {
      console.log('  Coffre vide : rien à déchiffrer, test non concluant mais non bloquant');
      return;
    }

    let déchiffrés = 0;
    let échecs = 0;

    for (const cipher of ciphers) {
      // Un item peut porter sa propre clé, elle-même enveloppée par la clé du
      // coffre. Le cas échéant, c'est elle qui déchiffre les champs.
      let itemKey = userKey;
      if (cipher.key) {
        itemKey = new SymmetricCryptoKey(await decryptBytes(EncString.parse(cipher.key), userKey));
      }

      const name = await decryptStringOrNull(cipher.name, itemKey, () => {
        échecs++;
      });

      if (name !== null) {
        déchiffrés++;
        // Seule la longueur est journalisée : le contenu reste secret.
        console.log(`    item de type ${cipher.type} — nom déchiffré, ${name.length} caractère(s)`);
      }
    }

    console.log(`  ${déchiffrés} déchiffré(s), ${échecs} échec(s)`);
    expect(échecs).toBe(0);
    expect(déchiffrés).toBe(ciphers.length);
  });
});

describe.skipIf(configured)('interopérabilité Vaultwarden', () => {
  it('est ignorée faute de configuration', () => {
    console.log(
      '  Test d’interopérabilité ignoré. Définir ZWARDEN_TEST_SERVER, ' +
        'ZWARDEN_TEST_EMAIL et ZWARDEN_TEST_PASSWORD pour l’activer.',
    );
    expect(configured).toBe(false);
  });
});
