import { STUB_GENESIS } from './anchor-stub.js';

// why: the anchor client trusts a service key list only when it chains to a genesis pin; the
// compiled pin is the production service's. In-process calls against the test stub read this
// (KRONICLE_ANCHOR_GENESIS); spawned CLIs get a clean env and pass it themselves.
process.env['KRONICLE_ANCHOR_GENESIS'] = STUB_GENESIS;
