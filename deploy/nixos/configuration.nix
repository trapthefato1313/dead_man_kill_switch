# deploy/nixos/configuration.nix
#
# Host de referência de um nó MailNet P2P. STATUS: [PLANO], não testado neste ambiente.
#
# Implantação nativa (sem Docker) e rollback:
#
#   # primeiro deploy
#   sudo nixos-rebuild switch --flake /etc/mailnet#node
#
#   # atualizar (atómico)
#   sudo nixos-rebuild switch --flake /etc/mailnet#node
#
#   # reverter para a geração anterior
#   sudo nixos-rebuild --rollback switch
#
#   # listar gerações e escolher uma
#   sudo nix-env --list-generations --profile /nix/var/nix/profiles/system
#   sudo /nix/var/nix/profiles/system-<N>-link/bin/switch-to-configuration switch
#
# Dados e filas ficam em /var/lib/mailnet e NUNCA na store Nix, por isso sobrevivem a
# qualquer switch/rollback.
{ config, pkgs, lib, ... }:

{
  # Nó MailNet (ver mailnet.nix).
  services.mailnet = {
    enable = true;
    mode = "prototype";          # trocar para "daemon" quando o binário Rust existir
    nodeName = "node-01";
    bind = "0.0.0.0";            # 127.0.0.1 para testar só local
    port = 2525;
    openFirewall = false;        # abrir explicitamente quando fizer sentido
    # Segredo gerido por agenix (criar a chave privada Ed25519 do nó):
    # identityKeyFile = config.age.secrets.mailnetNodeKey.path;
  };

  # Segredos fora do repo (agenix): desencriptados apenas no host.
  age.secrets.mailnetNodeKey = {
    file = ./secrets/mailnet-node-key.age;
    owner = "mailnet";
    group = "mailnet";
    mode = "0600";
  };

  # Base mínima e reproduzível. Sem Docker.
  nix.settings.experimental-features = [ "nix-command" "flakes" ];
  nix.gc = {
    automatic = true;
    dates = "weekly";
    options = "--delete-older-than 30d";
  };

  # SSH: chaves apenas, sem password (hardening mínimo).
  services.openssh = {
    enable = true;
    settings = {
      PasswordAuthentication = false;
      PermitRootLogin = "no";
    };
  };

  networking.firewall.enable = true;

  system.stateVersion = "24.11";
}
