/**
 * Copyright 2026 Redpanda Data, Inc.
 *
 * Use of this software is governed by the Business Source License
 * included in the file https://github.com/redpanda-data/redpanda/blob/dev/licenses/bsl.md
 *
 * As of the Change Date specified in that file, in accordance with
 * the Business Source License, use of this software will be governed
 * by the Apache License, Version 2.0
 */

import { afterEach, describe, expect, test } from 'vitest';

import { Route } from './__root';
import { useApiStore } from '../state/backend-api';

type RedirectError = Response & { options: { to: string; replace: boolean } };

function runBeforeLoad(pathname: string) {
  return Route.options.beforeLoad?.({ location: { pathname } } as never);
}

describe('root route auth guard', () => {
  afterEach(() => {
    useApiStore.setState({ userData: undefined });
  });

  test('redirects a protected route to the login page once the user is known to be unauthenticated', () => {
    expect.assertions(2);
    useApiStore.setState({ userData: null });

    try {
      runBeforeLoad('/topics');
    } catch (error) {
      const redirect = error as RedirectError;
      expect(redirect.options.to).toBe('/login');
      expect(redirect.options.replace).toBe(true);
    }
  });

  test('redirects even when the path carries a trailing slash, so a search-param write cannot bounce back', () => {
    expect.assertions(1);
    useApiStore.setState({ userData: null });

    try {
      runBeforeLoad('/topics/');
    } catch (error) {
      expect((error as RedirectError).options.to).toBe('/login');
    }
  });

  test('lets the login page and its callback routes through', () => {
    useApiStore.setState({ userData: null });

    expect(() => runBeforeLoad('/login')).not.toThrow();
    expect(() => runBeforeLoad('/login/')).not.toThrow();
    expect(() => runBeforeLoad('/login/callbacks/oidc')).not.toThrow();
  });

  test('does not redirect while the identity is still unknown or already resolved', () => {
    useApiStore.setState({ userData: undefined });
    expect(() => runBeforeLoad('/topics')).not.toThrow();

    useApiStore.setState({ userData: { displayName: 'test' } as never });
    expect(() => runBeforeLoad('/topics')).not.toThrow();
  });
});
