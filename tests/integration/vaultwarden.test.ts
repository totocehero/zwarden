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
import { decryptBytes, encryptString } from '../../src/core/crypto/cryptoService.js';
import {
  HashPurpose,
  KdfType,
  type KdfConfig,
  deriveMasterKey,
  derivePasswordHash,
  stretchMasterKey,
} from '../../src/core/crypto/kdf.js';
import {
  buildCipherUpdatePayload,
  decryptCipherDetails,
  decryptCipherList,
  decryptCipherOverview,
} from '../../src/core/vault/cipherService.js';
import { unlock } from '../../src/core/vault/session.js';

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
    const serverHash = await derivePasswordHash(
      masterKey,
      PASSWORD!,
      HashPurpose.ServerAuthorization,
    );
    session = await client.login(EMAIL!, serverHash);

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

  it("l'orchestrateur unlock() reproduit le chemin manuel", async () => {
    // Le chemin pas-à-pas ci-dessus valide chaque maillon ; celui-ci valide
    // l'enchaînement packagé que l'extension utilisera réellement.
    const résultat = await unlock(client, EMAIL!, PASSWORD!);

    expect(résultat.userKey.toBase64()).toBe(userKey.toBase64());
    expect(résultat.session.accessToken.length).toBeGreaterThan(0);
    expect(résultat.localPasswordHash.length).toBeGreaterThan(0);

    résultat.userKey.destroy();
    console.log('  unlock() : clé de coffre identique au chemin manuel');
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

      const erreurs: unknown[] = [];
      const surErreur = (e: unknown) => erreurs.push(e);
      const vue = await decryptCipherOverview(relu!, userKey, surErreur);
      const détails = await decryptCipherDetails(relu!, userKey, surErreur);

      expect(erreurs).toHaveLength(0);
      expect(vue.name).toBe(marqueur);
      expect(détails.username).toBe('utilisateur@test.local');
      expect(détails.password).toBe(motDePasse);

      console.log('  Aller-retour validé : nom, utilisateur et mot de passe identiques');

      // Mise à jour : nouveau nom et nouveau mot de passe, poussés puis relus
      // par une synchronisation complète — le chemin exact de l'édition dans
      // la popup.
      const marqueurModifié = `${marqueur}-modifié`;
      const nouveauMotDePasse = crypto.randomUUID();
      const payload = await buildCipherUpdatePayload(
        relu!,
        {
          name: marqueurModifié,
          username: 'utilisateur@test.local',
          password: nouveauMotDePasse,
          totp: '',
          notes: 'Item de test Zwarden, supprimé automatiquement.',
          uris: ['https://test.local'],
        },
        userKey,
        true,
      );
      await client.updateCipher(session.accessToken, créé.id, payload);

      const sync2 = await client.sync(session.accessToken);
      const relu2 = (sync2.ciphers ?? []).find((c) => c.id === créé.id);
      expect(relu2).toBeDefined();

      const vue2 = await decryptCipherOverview(relu2!, userKey, surErreur);
      const détails2 = await decryptCipherDetails(relu2!, userKey, surErreur);
      expect(erreurs).toHaveLength(0);
      expect(vue2.name).toBe(marqueurModifié);
      expect(détails2.password).toBe(nouveauMotDePasse);

      console.log('  Mise à jour poussée, relue et revalidée');
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

    // Le service de la couche coffre gère la clé par item et la tolérance de
    // casse ; c'est le chemin que l'extension utilisera réellement.
    let échecs = 0;
    const vues = await decryptCipherList(ciphers, userKey, () => {
      échecs++;
    });

    for (const vue of vues) {
      if (vue.name !== null) {
        // Seule la longueur est journalisée : le contenu reste secret.
        console.log(
          `    item de type ${vue.type} — nom déchiffré, ${vue.name.length} caractère(s)`,
        );
      }
    }

    const déchiffrés = vues.filter((v) => v.name !== null).length;
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
