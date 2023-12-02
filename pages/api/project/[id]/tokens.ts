import { createServerSupabaseClient } from '@supabase/auth-helpers-nextjs';
import type { NextApiRequest, NextApiResponse } from 'next';
import { isPresent } from 'ts-is-present';

import { withProjectAccess } from '@/lib/middleware/common';
import { createServiceRoleSupabaseClient } from '@/lib/supabase';
import { generateKey } from '@/lib/utils';
import { Database } from '@/types/supabase';
import {
  DbDecryptedToken,
  DbEncryptedToken,
  Project,
  Token,
} from '@/types/types';

type Data =
  | {
      status?: string;
      error?: string;
    }
  | Token[]
  | Token
  | DbEncryptedToken;

const allowedMethods = ['GET', 'POST', 'DELETE'];

const toToken = (decryptedToken: DbDecryptedToken): Token | undefined => {
  if (
    !decryptedToken.id ||
    !decryptedToken.inserted_at ||
    !decryptedToken.project_id ||
    !decryptedToken.decrypted_value
  ) {
    return undefined;
  }
  return {
    id: decryptedToken.id,
    insertedAt: decryptedToken.inserted_at,
    projectId: decryptedToken.project_id,
    value: decryptedToken.decrypted_value,
  };
};

const supabaseAdmin = createServiceRoleSupabaseClient();

export default withProjectAccess(
  allowedMethods,
  async (req: NextApiRequest, res: NextApiResponse<Data>) => {
    const sessionSupabase = createServerSupabaseClient<Database>({ req, res });
    const {
      data: { session },
    } = await sessionSupabase.auth.getSession();

    if (!session?.user) {
      return res.status(401).json({ error: 'Unauthorized' });
    }

    const projectId = req.query.id as Project['id'];

    if (req.method === 'GET') {
      const { data: tokens, error } = await supabaseAdmin
        .from('decrypted_tokens')
        .select('*')
        .eq('project_id', projectId);

      if (error) {
        return res.status(400).json({ error: error.message });
      }

      if (!tokens) {
        return res.status(404).json({ error: 'No tokens found.' });
      }

      return res.status(200).json(tokens.map(toToken).filter(isPresent));
    } else if (req.method === 'POST') {
      const value = generateKey();
      const { error, data } = await supabaseAdmin
        .from('tokens')
        .insert([
          {
            value: '', // For backwards compatibility
            encrypted_value: value,
            project_id: projectId,
            created_by: session.user.id,
          },
        ])
        .select('*')
        .limit(1)
        .maybeSingle();

      if (error) {
        return res.status(400).json({ error: error.message });
      }

      if (!data) {
        return res.status(400).json({ error: 'Error generating token.' });
      }

      return res.status(200).json(data);
    } else if (req.method === 'DELETE') {
      const { error } = await supabaseAdmin
        .from('tokens')
        .delete()
        .eq('id', req.body.id);
      if (error) {
        return res.status(400).json({ error: error.message });
      }

      return res.status(200).json({ status: 'ok' });
    }

    return res.status(400).json({ error: 'unknown' });
  },
);
