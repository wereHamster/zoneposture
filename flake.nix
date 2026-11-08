{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
  };

  outputs =
    {
      nixpkgs,
      ...
    }:
    let
      forAllSystems =
        function: nixpkgs.lib.genAttrs nixpkgs.lib.systems.flakeExposed (system: function nixpkgs.legacyPackages.${system});

    in
    {
      devShells = forAllSystems (pkgs: {
        default = pkgs.mkShell {
          nativeBuildInputs = with pkgs; [
            rustc
            cargo
            rustfmt
            clippy
            rust-analyzer
          ];
        };
      });
    };
}
