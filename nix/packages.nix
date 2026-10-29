# nix/packages.nix — Lliam-GOV Agent package built with uv2nix
{ inputs, ... }:
{
  perSystem =
    {
      pkgs,
      lib,
      inputs',
      ...
    }:
    let
      minimal = pkgs.callPackage ./lliam-gov-agent.nix {
        inherit (inputs) uv2nix pyproject-nix pyproject-build-systems;
        npm-lockfile-fix = inputs'.npm-lockfile-fix.packages.default;
        # Only embed clean revs — dirtyRev doesn't represent any upstream
        # commit, so comparing it would always claim "update available".
        rev = inputs.self.rev or null;
      };

      # All platform-portable optional integrations pre-built.
      full = minimal.override {
        extraDependencyGroups = [
          "anthropic"
          "azure-identity"
          "bedrock"
          "daytona"
          "edge-tts"
          "exa"
          "fal"
          "firecrawl"
          "hindsight"
          "honcho"
          "modal"
          "parallel-web"
          "tts-premium"
          "voice"
        ];
      };
    in
    {
      packages = {
        default = full;

        inherit minimal;

        tui = full.lliamTui;
        web = full.lliamWeb;
        desktop = full.lliamDesktop;
      };
    };
}
