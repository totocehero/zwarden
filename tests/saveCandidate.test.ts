/**
 * @file Rapprochement d'un identifiant saisi avec le coffre.
 *
 * `findSaveCandidate` décide entre « créer un item » et « mettre à jour
 * celui-ci ». Une erreur de sens n'est pas un défaut d'affichage : elle
 * écrase un mot de passe encore valide, ou en crée un doublon silencieux.
 * D'où l'insistance sur l'origine stricte, reprise de la règle 2 du §4 de
 * `docs/EXTENSION.md`.
 */

import { describe, expect, it } from 'vitest';

import type { CipherOverview } from '../src/core/vault/cipherService.js';
import { decideProposal, findSaveCandidate } from '../src/core/vault/cipherService.js';
import { matchesOrigin } from '../src/core/vault/uriMatch.js';

function item(id: string, username: string, uris: string[]): CipherOverview {
  return {
    id,
    type: 1,
    name: id,
    username,
    uris,
    hasPasskey: false,
    hasTotp: false,
    reprompt: false,
    organizationId: null,
    folderId: null,
    collectionIds: [],
  };
}

describe('findSaveCandidate', () => {
  const perso = item('perso', 'moi@exemple.fr', ['https://github.com']);
  const pro = item('pro', 'moi@boite.fr', ['https://github.com']);
  const ailleurs = item('ailleurs', 'moi@exemple.fr', ['https://gitlab.com']);
  const coffre = [perso, pro, ailleurs];

  const chercher = (origin: string, username: string) =>
    findSaveCandidate(coffre, origin, username, matchesOrigin);

  it('rapproche l’item de même origine et même identifiant', () => {
    expect(chercher('https://github.com', 'moi@exemple.fr')).toBe(perso);
  });

  it('distingue deux comptes du même site', () => {
    expect(chercher('https://github.com', 'moi@boite.fr')).toBe(pro);
  });

  it('ignore la casse et les espaces de l’identifiant', () => {
    expect(chercher('https://github.com', '  MOI@Exemple.FR ')).toBe(perso);
  });

  it('ne rapproche rien pour un identifiant inconnu sur ce site', () => {
    // Second compte : il faut créer, surtout pas écraser.
    expect(chercher('https://github.com', 'autre@exemple.fr')).toBeNull();
  });

  it('ne rapproche rien sur une autre origine', () => {
    expect(chercher('https://bitbucket.org', 'moi@exemple.fr')).toBeNull();
  });

  it('n’accepte pas une origine voisine', () => {
    // La règle §4 : origine stricte. `github.com.attaquant.com` ne doit
    // rapprocher aucun item, sous peine d'y écraser un mot de passe.
    expect(chercher('https://github.com.attaquant.com', 'moi@exemple.fr')).toBeNull();
    expect(chercher('http://github.com', 'moi@exemple.fr')).toBeNull();
  });

  it('ne rapproche rien sans identifiant détecté', () => {
    expect(chercher('https://github.com', '')).toBeNull();
    expect(chercher('https://github.com', '   ')).toBeNull();
  });
});

describe('decideProposal', () => {
  const capture = 'nouveau-secret';

  it('propose la création quand rien ne se rapproche', () => {
    expect(decideProposal(null, capture, null)).toEqual({ kind: 'creation' });
  });

  /**
   * Le cas le plus fréquent : une connexion ordinaire. Le taire est ce qui donne
   * du sens à la pastille — s'allumer à chaque connexion réussie la rendrait
   * insignifiante.
   */
  it('se tait quand le coffre a déjà ce mot de passe', () => {
    const existant = item('i1', 'alice', ['https://exemple.fr']);
    expect(decideProposal(existant, capture, capture)).toEqual({ kind: 'aucune' });
  });

  it('propose la mise à jour quand le mot de passe a changé', () => {
    const existant = item('i1', 'alice', ['https://exemple.fr']);
    expect(decideProposal(existant, capture, 'ancien')).toEqual({
      kind: 'miseAJour',
      item: existant,
    });
  });

  /**
   * Item illisible : se taire sur la foi d'une comparaison impossible ferait
   * perdre la saisie. On propose, l'utilisateur tranche.
   */
  it('propose la mise à jour quand l’item existant est illisible', () => {
    const existant = item('i1', 'alice', ['https://exemple.fr']);
    expect(decideProposal(existant, capture, null)).toEqual({
      kind: 'miseAJour',
      item: existant,
    });
  });
});
