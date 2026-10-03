import type { IncomingMessage, ServerResponse } from 'node:http';
import type Provider from 'oidc-provider';

/** What the host's sign-in established. The server records it as given and never raises it. */
export interface SignInResult {
  accountId: string;
  /** RFC 8176 method references for the factors actually used, as the host computed them. */
  amr: string[];
  /** The assurance level the host computed for this sign-in. */
  acr: string;
  /** When the sign-in happened, in seconds since the epoch. Defaults to now. */
  authTime?: number;
  /** Keep the provider's session beyond the browser session. Defaults to false. */
  remember?: boolean;
}

/** The pending prompt, so the host knows whether to show sign-in or consent. */
export interface PendingInteraction {
  uid: string;
  prompt: 'login' | 'consent';
  clientId: string;
  /** Requested scopes. */
  scope: string;
  /** Set once sign-in has finished; the account that consent is for. */
  accountId?: string;
  /**
   * True when a device (RFC 8628) is asking. Approving gives a device a long-lived grant, so
   * the host applies step-up here.
   */
  deviceFlow: boolean;
}

export interface InteractionHelpers {
  details(req: IncomingMessage, res: ServerResponse): Promise<PendingInteraction>;
  finishLogin(req: IncomingMessage, res: ServerResponse, result: SignInResult): Promise<void>;
  finishConsent(req: IncomingMessage, res: ServerResponse): Promise<void>;
  /** End the interaction with an error. A failed sign-in never falls through to another method. */
  fail(
    req: IncomingMessage,
    res: ServerResponse,
    error?: 'access_denied' | 'login_required' | 'consent_required',
    description?: string
  ): Promise<void>;
}

export function interactionHelpers(provider: Provider): InteractionHelpers {
  const pending = async (
    req: IncomingMessage,
    res: ServerResponse,
    expected?: 'login' | 'consent'
  ): Promise<Awaited<ReturnType<Provider['interactionDetails']>>> => {
    const interaction = await provider.interactionDetails(req, res);
    if (expected && interaction.prompt.name !== expected) {
      throw new Error(
        `interaction ${interaction.uid} is at ${interaction.prompt.name}, not ${expected}`
      );
    }
    return interaction;
  };

  return {
    async details(req, res) {
      const interaction = await pending(req, res);
      const prompt = interaction.prompt.name;
      if (prompt !== 'login' && prompt !== 'consent') {
        throw new Error(`unsupported prompt ${prompt}`);
      }
      return {
        uid: interaction.uid,
        prompt,
        clientId: String(interaction.params.client_id),
        scope: typeof interaction.params.scope === 'string' ? interaction.params.scope : '',
        accountId: interaction.session?.accountId,
        deviceFlow: Boolean((interaction as { deviceCode?: string }).deviceCode)
      };
    },

    async finishLogin(req, res, result) {
      await pending(req, res, 'login');
      await provider.interactionFinished(
        req,
        res,
        {
          login: {
            accountId: result.accountId,
            amr: result.amr,
            acr: result.acr,
            ts: result.authTime ?? Math.floor(Date.now() / 1000),
            remember: result.remember ?? false
          }
        },
        { mergeWithLastSubmission: false }
      );
    },

    async finishConsent(req, res) {
      const interaction = await pending(req, res, 'consent');
      const accountId = interaction.session?.accountId;
      if (!accountId) throw new Error(`interaction ${interaction.uid} has no signed-in account`);

      const clientId = String(interaction.params.client_id);
      const grant =
        (interaction.grantId ? await provider.Grant.find(interaction.grantId) : undefined) ??
        new provider.Grant({ accountId, clientId });

      const details = interaction.prompt.details as {
        missingOIDCScope?: string[];
        missingOIDCClaims?: string[];
        missingResourceScopes?: Record<string, string[]>;
      };
      if (details.missingOIDCScope) grant.addOIDCScope(details.missingOIDCScope.join(' '));
      if (details.missingOIDCClaims) grant.addOIDCClaims(details.missingOIDCClaims);
      for (const [resource, scopes] of Object.entries(details.missingResourceScopes ?? {})) {
        grant.addResourceScope(resource, scopes.join(' '));
      }

      const grantId = await grant.save();
      await provider.interactionFinished(
        req,
        res,
        { consent: { grantId } },
        { mergeWithLastSubmission: true }
      );
    },

    async fail(req, res, error = 'access_denied', description) {
      await pending(req, res);
      await provider.interactionFinished(
        req,
        res,
        { error, error_description: description },
        { mergeWithLastSubmission: false }
      );
    }
  };
}
