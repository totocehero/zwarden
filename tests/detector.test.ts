// @vitest-environment jsdom

/**
 * @file Tests des heuristiques du détecteur d'identifiants.
 *
 * Ces cas étaient jusqu'ici invérifiables autrement qu'à la main sur un vrai
 * site — et c'est exactement pour cette raison qu'un commentaire du détecteur
 * avait pu promettre une garde que le code n'appliquait pas. Ce fichier existe
 * pour que la promesse et le code ne puissent plus diverger discrètement.
 *
 * `offsetParent` n'existe pas sous jsdom, qui n'implémente aucune mise en page :
 * le test de visibilité est donc injecté. Les cas de champ masqué sont couverts
 * en le pilotant explicitement.
 */

import { describe, expect, it } from 'vitest';

import {
  type VisibilityTest,
  estBasculeAffichage,
  filledPasswords,
  findCapture,
  guessUsername,
} from '../src/content/heuristics.js';

/** Tout est visible : le cas normal d'une page de connexion affichée. */
const TOUT_VISIBLE: VisibilityTest = () => true;

/** Construit un sous-arbre détaché depuis du HTML, et rend son élément racine. */
function fragment(html: string): HTMLElement {
  const hote = document.createElement('div');
  hote.innerHTML = html;
  document.body.replaceChildren(hote);
  return hote;
}

/** Remplit les champs nommés, comme le ferait une saisie utilisateur. */
function saisir(racine: ParentNode, valeurs: Record<string, string>): void {
  for (const [nom, valeur] of Object.entries(valeurs)) {
    const champ = racine.querySelector<HTMLInputElement>(`[name="${nom}"]`);
    if (champ === null) {
      throw new Error(`Champ absent du fragment : ${nom}`);
    }
    champ.value = valeur;
  }
}

describe('findCapture — formulaire de connexion ordinaire', () => {
  it('capture l’identifiant et le mot de passe', () => {
    const f = fragment(`
      <form>
        <input name="u" type="text">
        <input name="p" type="password">
        <button type="submit">Se connecter</button>
      </form>`);
    saisir(f, { u: 'alice@exemple.fr', p: 'secret-1' });

    expect(findCapture(f, null, TOUT_VISIBLE)).toEqual({
      username: 'alice@exemple.fr',
      password: 'secret-1',
    });
  });

  it('ne capture rien sans mot de passe saisi', () => {
    const f = fragment('<form><input name="u" type="text"><input name="p" type="password"></form>');
    saisir(f, { u: 'alice', p: '' });

    expect(findCapture(f, null, TOUT_VISIBLE)).toBeNull();
  });

  it('ignore un champ mot de passe masqué', () => {
    const f = fragment(`
      <form>
        <input name="visible" type="password">
        <input name="cache" type="password">
      </form>`);
    saisir(f, { visible: '', cache: 'piège' });
    const masque: VisibilityTest = (el) => el.getAttribute('name') !== 'cache';

    expect(findCapture(f, null, masque)).toBeNull();
  });
});

describe('findCapture — création de compte', () => {
  it('capture quand les deux mots de passe concordent', () => {
    const f = fragment(`
      <form>
        <input name="u" type="email">
        <input name="p1" type="password">
        <input name="p2" type="password">
      </form>`);
    saisir(f, { u: 'a@b.fr', p1: 'identique', p2: 'identique' });

    expect(findCapture(f, null, TOUT_VISIBLE)?.password).toBe('identique');
  });

  /**
   * Saisie encore incomplète : le site va la refuser. Proposer un enregistrement
   * reviendrait à retenir un mot de passe qui n'a jamais été accepté.
   */
  it('ne capture rien quand la confirmation diffère', () => {
    const f = fragment(`
      <form>
        <input name="p1" type="password">
        <input name="p2" type="password">
      </form>`);
    saisir(f, { p1: 'secret-1', p2: 'secret-2' });

    expect(findCapture(f, null, TOUT_VISIBLE)).toBeNull();
  });
});

describe('estBasculeAffichage — le faux positif du repli sur le clic', () => {
  /**
   * Le cas qui motive toute cette garde : cliquer sur l'œil « afficher le mot de
   * passe » déclenchait une capture et allumait la pastille, alors que
   * l'utilisateur n'avait rien soumis.
   */
  it('écarte un œil « afficher » logé dans le bloc du champ', () => {
    const f = fragment(`
      <form>
        <input name="u" type="text">
        <div class="champ">
          <input name="p" type="password">
          <button type="button" class="oeil">afficher</button>
        </div>
        <button type="submit">Entrer</button>
      </form>`);
    saisir(f, { u: 'alice', p: 'secret-1' });
    const oeil = f.querySelector('.oeil')!;

    expect(findCapture(f, oeil, TOUT_VISIBLE)).toBeNull();
  });

  it('écarte tout bouton à deux états', () => {
    const f = fragment(`
      <form>
        <input name="p" type="password">
        <button type="button" aria-pressed="false" class="bascule">voir</button>
      </form>`);
    saisir(f, { p: 'secret-1' });
    const bascule = f.querySelector('.bascule')!;

    expect(findCapture(f, bascule, TOUT_VISIBLE)).toBeNull();
  });

  it('laisse passer le bouton de soumission', () => {
    const f = fragment(`
      <form>
        <input name="u" type="text">
        <input name="p" type="password">
        <button type="submit" class="envoi">Se connecter</button>
      </form>`);
    saisir(f, { u: 'alice', p: 'secret-1' });
    const envoi = f.querySelector('.envoi')!;

    expect(findCapture(f, envoi, TOUT_VISIBLE)?.password).toBe('secret-1');
  });

  /** Un bouton hors du bloc du champ reste une soumission plausible. */
  it('laisse passer un bouton sans type, hors du bloc du champ', () => {
    const f = fragment(`
      <form>
        <div><input name="p" type="password"></div>
        <button class="action">Continuer</button>
      </form>`);
    saisir(f, { p: 'secret-1' });
    const action = f.querySelector('.action')!;

    expect(estBasculeAffichage(action, f.querySelector('[name="p"]')!)).toBe(false);
  });
});

describe('guessUsername', () => {
  it('préfère l’annotation explicite du site', () => {
    const f = fragment(`
      <form>
        <input name="parasite" type="text">
        <input name="vrai" type="text" autocomplete="username">
        <input name="p" type="password">
      </form>`);
    saisir(f, { parasite: 'à-ignorer', vrai: 'alice', p: 'x' });

    expect(guessUsername(f, f.querySelector('[name="p"]')!, TOUT_VISIBLE)).toBe('alice');
  });

  it('retient à défaut le dernier champ rempli avant le mot de passe', () => {
    const f = fragment(`
      <form>
        <input name="a" type="text">
        <input name="b" type="email">
        <input name="p" type="password">
        <input name="apres" type="text">
      </form>`);
    saisir(f, { a: 'premier', b: 'second@exemple.fr', p: 'x', apres: 'après' });

    expect(guessUsername(f, f.querySelector('[name="p"]')!, TOUT_VISIBLE)).toBe(
      'second@exemple.fr',
    );
  });

  /**
   * Certains sites placent le champ identifiant après le mot de passe dans le
   * document tout en l'affichant avant. À défaut de candidat précédent, le
   * premier champ rempli vaut mieux qu'une chaîne vide.
   */
  it('se rabat sur le premier champ rempli si aucun ne précède', () => {
    const f = fragment(`
      <form>
        <input name="p" type="password">
        <input name="u" type="text">
      </form>`);
    saisir(f, { p: 'x', u: 'alice' });

    expect(guessUsername(f, f.querySelector('[name="p"]')!, TOUT_VISIBLE)).toBe('alice');
  });

  /**
   * Le bogue constaté à l'usage : « il m'a mis le mot de passe dans le login ».
   *
   * Motif « afficher le mot de passe » à deux champs — un `password` et un `text`
   * miroir dont le site bascule la visibilité. Le miroir est rempli, visible, et
   * placé avant le champ mot de passe : c'était donc le candidat parfait pour la
   * règle de proximité, qui livrait le mot de passe comme identifiant. L'item
   * créé portait alors le mot de passe en clair dans son champ identifiant.
   */
  it('n’accepte jamais un champ qui contient le mot de passe', () => {
    const f = fragment(`
      <form>
        <input name="u" type="text">
        <input name="miroir" type="text">
        <input name="p" type="password">
      </form>`);
    saisir(f, { u: 'alice@exemple.fr', miroir: 'S3cret!', p: 'S3cret!' });

    expect(findCapture(f, null, TOUT_VISIBLE)).toEqual({
      username: 'alice@exemple.fr',
      password: 'S3cret!',
    });
  });

  /** Même piège, sans identifiant à récupérer : mieux vaut vide que faux. */
  it('rend vide plutôt que le mot de passe quand le miroir est seul', () => {
    const f = fragment(`
      <form>
        <input name="miroir" type="text">
        <input name="p" type="password">
      </form>`);
    saisir(f, { miroir: 'S3cret!', p: 'S3cret!' });

    expect(findCapture(f, null, TOUT_VISIBLE)?.username).toBe('');
  });

  /** Le site annonce lui-même le champ comme un mot de passe : on le croit. */
  it('écarte un champ annoté comme mot de passe', () => {
    const f = fragment(`
      <form>
        <input name="nouveau" type="text" autocomplete="new-password">
        <input name="p" type="password">
      </form>`);
    saisir(f, { nouveau: 'autre-chose', p: 'S3cret!' });

    expect(findCapture(f, null, TOUT_VISIBLE)?.username).toBe('');
  });

  /**
   * Hors formulaire, le balayage porte sur tout le document : un champ de
   * recherche où l'utilisateur aurait collé son mot de passe ne doit pas
   * ressortir comme identifiant.
   */
  it('ne reprend pas le mot de passe trouvé ailleurs dans la page', () => {
    fragment(`
      <div>
        <input name="recherche" type="text">
        <div><input name="p" type="password"></div>
      </div>`);
    saisir(document, { recherche: 'S3cret!', p: 'S3cret!' });

    expect(findCapture(document, null, TOUT_VISIBLE)?.username).toBe('');
  });

  it('rend une chaîne vide quand rien ne ressemble à un identifiant', () => {
    const f = fragment('<form><input name="p" type="password"></form>');
    saisir(f, { p: 'x' });

    expect(guessUsername(f, f.querySelector('[name="p"]')!, TOUT_VISIBLE)).toBe('');
  });
});

describe('filledPasswords', () => {
  it('rend les champs remplis dans l’ordre du document', () => {
    const f = fragment(`
      <form>
        <input name="p1" type="password">
        <input name="vide" type="password">
        <input name="p2" type="password">
      </form>`);
    saisir(f, { p1: 'un', vide: '', p2: 'deux' });

    expect(filledPasswords(f, TOUT_VISIBLE).map((i) => i.value)).toEqual(['un', 'deux']);
  });
});
