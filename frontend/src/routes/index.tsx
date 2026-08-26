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

import { createFileRoute, redirect } from '@tanstack/react-router';

export const Route = createFileRoute('/')({
  // Redirect from the route, not from a rendered `<Navigate>`. `<Navigate>` fires
  // its navigation from a layout effect whose dependency is the props object, so a
  // fresh `<Navigate replace to="/overview" />` element re-navigates on every
  // commit. While the root auth guard keeps rejecting the pending navigation the
  // component stays mounted, and that turns into an endless navigate/render loop
  // that pins the main thread and never paints a page.
  beforeLoad: () => {
    throw redirect({ replace: true, to: '/overview' });
  },
  component: () => null,
});
