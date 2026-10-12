# deploy/nixos/mailnet.nix
#
# Módulo NixOS de referência para um nó MailNet P2P.
# STATUS: [PLANO]. Não testado neste ambiente. `mode = "prototype"` corre o protótipo
# Python já existente ([EXISTE]); `mode = "daemon"` destina-se ao daemon Rust ([PLANO]).
#
# Princípios de deploy imutável aplicados aqui:
#   - binários/serviço geridos pelo Nix (nada instalado à mão);
#   - dados persistentes só em /var/lib/mailnet (fora da store Nix);
#   - segredos via agenix, desencriptados só no host;
#   - hardening systemd e utilizador sem privilégios.
{ config, lib, pkgs, inputs, ... }:

with lib;

let
  cfg = config.services.mailnet;

  # Protótipo Python existente no repo (usado em mode = "prototype").
  prototype = pkgs.runCommand "mailnet-prototype" { } ''
    mkdir -p $out/lib
    cp -r ${inputs.self}/dmks $out/lib/dmks
  '';

  prototypeArgs = [
    "-m" "dmks" "sink"
    "--bind" cfg.bind
    "--port" (toString cfg.port)
    "--spool" "${cfg.dataDir}/spool"
    "--name" cfg.nodeName
  ];

  daemonArgs = [ "run" "--config" "/etc/mailnet/config.toml" ];

  execStart =
    if cfg.mode == "prototype" then
      "${pkgs.python3}/bin/python3 ${escapeShellArgs prototypeArgs}"
    else
      "${lib.getExe cfg.package} ${escapeShellArgs daemonArgs}";

in {
  options.services.mailnet = {
    enable = mkEnableOption "MailNet P2P node";

    mode = mkOption {
      type = types.enum [ "prototype" "daemon" ];
      default = "prototype";
      description = "prototype = Python (existente); daemon = binário Rust (a implementar)";
    };

    package = mkOption {
      type = types.package;
      default = throw "define services.mailnet.package (daemon Rust ainda não existe)";
      description = "Pacote do daemon MailNet (mode = daemon).";
    };

    nodeName = mkOption { type = types.str; default = "node"; };
    bind = mkOption { type = types.str; default = "127.0.0.1"; };
    port = mkOption { type = types.port; default = 2525; };
    dataDir = mkOption { type = types.path; default = "/var/lib/mailnet"; };
    identityKeyFile = mkOption {
      type = types.nullOr types.path;
      default = null;
      description = "Ficheiro agenix com a chave privada Ed25519 do nó.";
    };
    openFirewall = mkOption { type = types.bool; default = false; };
  };

  config = mkIf cfg.enable {
    users.users.mailnet = {
      isSystemUser = true;
      group = "mailnet";
      home = cfg.dataDir;
      createHome = false;
    };
    users.groups.mailnet = { };

    systemd.tmpfiles.rules = [
      "d ${cfg.dataDir}          0700 mailnet mailnet -"
      "d ${cfg.dataDir}/spool    0700 mailnet mailnet -"
      "d ${cfg.dataDir}/queue    0700 mailnet mailnet -"
      "d ${cfg.dataDir}/keys     0700 mailnet mailnet -"
    ];

    systemd.services.mailnet = {
      description = "MailNet P2P node (${cfg.mode})";
      wantedBy = [ "multi-user.target" ];
      after = [ "network-online.target" ];
      wants = [ "network-online.target" ];

      environment.PYTHONPATH = mkIf (cfg.mode == "prototype") "${prototype}/lib";

      serviceConfig = {
        Type = "simple";
        User = "mailnet";
        Group = "mailnet";
        WorkingDirectory = cfg.dataDir;
        ExecStart = execStart;
        Restart = "on-failure";
        RestartSec = "5s";

        # Hardening (SECURITY.md §4)
        NoNewPrivileges = true;
        ProtectSystem = "strict";
        ProtectHome = true;
        PrivateTmp = true;
        PrivateDevices = true;
        ProtectKernelTunables = true;
        ProtectControlGroups = true;
        RestrictAddressFamilies = [ "AF_INET" "AF_INET6" "AF_UNIX" ];
        RestrictNamespaces = true;
        LockPersonality = true;
        MemoryDenyWriteExecute = true;
        SystemCallArchitectures = "native";
        ReadWritePaths = [ cfg.dataDir ];
      } // (optionalAttrs (cfg.identityKeyFile != null) {
        LoadCredential = "node.key:${cfg.identityKeyFile}";
      });
    };

    networking.firewall.allowedTCPPorts = mkIf cfg.openFirewall [ cfg.port ];

    # Config declarativa do nó (imutável, versionada).
    environment.etc."mailnet/config.toml".text = ''
      [node]
      name = "${cfg.nodeName}"
      bind = "${cfg.bind}"
      port = ${toString cfg.port}
      data_dir = "${cfg.dataDir}"

      [transport]
      tls = true
      dedup = "message-id+content-hash"
      retry = "5x backoff 1m..8h"
      queue_ttl_hours = 72
    '';
  };
}
