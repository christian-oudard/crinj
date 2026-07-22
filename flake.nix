{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  };

  outputs = { self, nixpkgs }: let
    system = "x86_64-linux";
    pkgs = import nixpkgs { inherit system; };

    crinj = pkgs.buildGoModule {
      pname = "crinj";
      version = "0.1.0";
      src = ./.;

      # Pure-Go SQLite (modernc.org/sqlite) keeps cgo off and the build fast.
      env.CGO_ENABLED = "0";

      vendorHash = "sha256-5YluHJOf6JfdFsglR9EKrTwZmw558eglAiXhwmFTdsc=";

      ldflags = [
        "-s" "-w"
        "-X" "main.commit=${self.shortRev or self.dirtyShortRev or "unknown"}"
      ];
    };

  in {
    packages.${system} = {
      inherit crinj;
      default = crinj;
    };

    nixosModules.default = { config, lib, ... }:
    let
      cfg = config.services.crinj;
    in {
      options.services.crinj = {
        enable = lib.mkEnableOption "crinj credential injection proxy";

        port = lib.mkOption {
          type = lib.types.port;
          default = 10255;
          description = "Port for the MITM proxy";
        };

        configFile = lib.mkOption {
          type = lib.types.path;
          description = "Path to the config TOML file";
        };

        dataDir = lib.mkOption {
          type = lib.types.str;
          default = "/var/lib/crinj";
          description = "Directory for CA certificates";
        };

        package = lib.mkPackageOption self.packages.${system} "default" {};

        openFirewall = lib.mkOption {
          type = lib.types.bool;
          default = false;
          description = "Open firewall port for the proxy";
        };
      };

      config = lib.mkIf cfg.enable {
        systemd.services.crinj = {
          description = "crinj credential injection proxy";
          after = [ "network.target" ];
          wantedBy = [ "multi-user.target" ];

          serviceConfig = {
            Type = "simple";
            ExecStart = "${cfg.package}/bin/crinj --port ${toString cfg.port} --data-dir ${cfg.dataDir} --config ${cfg.configFile}";
            StateDirectory = "crinj";
            DynamicUser = true;
            Restart = "on-failure";
            RestartSec = 5;

            NoNewPrivileges = true;
            ProtectSystem = "strict";
            ProtectHome = "read-only";
            ReadWritePaths = [ cfg.dataDir ];
            PrivateTmp = true;
          };
        };

        networking.firewall = lib.mkIf cfg.openFirewall {
          allowedTCPPorts = [ cfg.port ];
        };
      };
    };

    devShells.${system}.default = pkgs.mkShell {
      packages = [ pkgs.go pkgs.gopls pkgs.gotools ];
    };
  };
}
