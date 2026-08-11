import * as Effect from "effect/Effect";

const SSH_URL_HOST = /^(ssh:\/\/(?:[^@/]*@)?)([^@:/]+)/iu;
const SCP_URL_HOST = /^((?:[^@:/]*@)?)([^@:/]{2,})(?=:(?!\/))/u;

const hostPattern = (remoteUrl: string): RegExp =>
  /^ssh:\/\//iu.test(remoteUrl) ? SSH_URL_HOST : SCP_URL_HOST;

export type SshConfigProbe = (host: string) => Effect.Effect<string>;

const HOSTNAME_TTL_MS = 5 * 60_000;
const effectiveHostnames = new Map<string, { readonly at: number; readonly hostname: string }>();

export const canonicalizeSshRemoteUrl = Effect.fnUntraced(function* (
  remoteUrl: string,
  probe: SshConfigProbe,
) {
  const host = hostPattern(remoteUrl).exec(remoteUrl)?.[2];
  if (host === undefined) return remoteUrl;

  const now = Date.now();
  const cached = effectiveHostnames.get(host);
  const hostname =
    (cached !== undefined && now - cached.at < HOSTNAME_TTL_MS ? cached.hostname : undefined) ??
    /^hostname[ \t]+(\S+)/imu.exec(yield* probe(host))?.[1] ??
    host;
  effectiveHostnames.set(host, { at: now, hostname });

  return hostname === host
    ? remoteUrl
    : remoteUrl.replace(hostPattern(remoteUrl), (_, prefix: string) => prefix + hostname);
});
