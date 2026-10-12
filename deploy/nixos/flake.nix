# deploy/nixos/flake.nix
#
# Flake de referência para nós MailNet P2P. STATUS: [PLANO].
# Reproduzibilidade: fixar as entradas (nix flake lock) e inspecionar os hashes.
{
  description = "MailNet P2P — deploy imutável (NixOS), sem Docker";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    agenix = {
      url = "github:ryantm/agenix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { self, nixpkgs, agenix }:
    let
      system = "x86_64-linux";
    in {
      # Módulo reutilizável: services.mailnet
      nixosModules.mailnet = import ./mailnet.nix;

      nixosConfigurations.node = nixpkgs.lib.nixosSystem {
        inherit system;
        specialArgs = { inherit self; };
        modules = [
          ./configuration.nix
          agenix.nixosModules.default
          self.nixosModules.mailnet
        ];
      };

      # [PLANO] pacotes reproduzíveis (daemon Rust); vazio enquanto não existe.
      packages.${system} = { };
    };
}
