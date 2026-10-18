// Typecheck stub for `react-native` (wired in tsconfig.json `paths`).
// react-native-nitro-modules' public types import `HostComponent`/`ViewProps`
// from react-native; resolving the real package would pull in RN's global
// augmentations, which conflict with ../spark/src once the dev `paths` mapping
// brings the sibling sources into this program. The real types are only needed
// inside a consuming React Native app.
export type HostComponent<Props> = abstract new (props: Props) => Props;
export type ViewProps = Record<string, unknown>;
