{
  config,
  lib,
  pkgs,
  ...
}: let
  cfg = config.secnix;
  secnix = pkgs.callPackage ../secnix.nix {};
  secretType = lib.types.submodule ({
    config,
    name,
    ...
  }: {
    options = {
      name = lib.mkOption {
        type = lib.types.str;
        default = name;
        description = "The name of the secret";
      };
      key = lib.mkOption {
        type = lib.types.str;
        description = "The key used in the secret file";
      };
      type = lib.mkOption {
        type = lib.types.enum ["yaml" "json" "yml" "binary"];
        description = "The type of the secret file";
        default = "yaml";
      };
      mode = lib.mkOption {
        type = lib.types.str;
        description = "The mode of the secret file";
        default = "600";
      };
      group = lib.mkOption {
        type = lib.types.nullOr lib.types.str;
        description = "The group that will own the secret file";
        default = null;
      };
      owner = lib.mkOption {
        type = lib.types.nullOr lib.types.str;
        description = "The user that will own the secret file";
        default = null;
      };
      link = lib.mkOption {
        type = lib.types.nullOr lib.types.str;
        description = "The link to the secret file";
        default = "${cfg.defaultSymlinkPath}/${name}";
      };
      source = lib.mkOption {
        type = lib.types.path;
        description = "The source of the secret file";
      };
    };
  });
  templateType = lib.types.submodule ({
    config,
    name,
    ...
  }: {
    options = {
      name = lib.mkOption {
        type = lib.types.str;
        default = name;
        description = "The name of the template";
      };
      source = lib.mkOption {
        type = lib.types.str;
        description = "The source of the template";
      };
      target = lib.mkOption {
        type = lib.types.str;
        description = "The target of the template";
      };
      copy = lib.mkOption {
        type = lib.types.bool;
        description = "Whether the template should be copied or linked";
        default = false;
      };
      mode = lib.mkOption {
        type = lib.types.str;
        description = "The mode of the template";
        default = "600";
      };
      group = lib.mkOption {
        type = lib.types.nullOr lib.types.str;
        description = "The group that will own the template";
        default = null;
      };
      owner = lib.mkOption {
        type = lib.types.nullOr lib.types.str;
        description = "The user that will own the template";
      };
    };
  });
  script = pkgs.writeShellScriptBin "secnix-activation" ''
    ${secnix}/bin/secnix ${manifest {
      secrets = cfg.secrets;
      templates = cfg.templates;
    }}
  '';

  manifest = {
    suffix ? "",
    secrets,
    templates,
  }:
    pkgs.writeTextFile {
      name = "manifest${suffix}.json";
      text = builtins.toJSON {
        version = 1;
        secrets = builtins.attrValues secrets;
        templates = builtins.attrValues templates;
        ssh_keys = cfg.sshKeys;
        write_manifest = true;
        secret_directory = cfg.mount;
      };
      checkPhase = ''
        ${secnix}/bin/secnix "$out" check
      '';
    };
in {
  options = {
    secnix = {
      secrets = lib.mkOption {
        type = lib.types.attrsOf secretType;
        default = {};
        description = "The secrets to be managed";
      };
      templates = lib.mkOption {
        type = lib.types.attrsOf templateType;
        default = {};
        description = "The templates to be managed";
      };
      sshKeys = lib.mkOption {
        type = lib.types.listOf lib.types.str;
        default = [];
        description = "The ssh keys used to decrypt the secrets";
      };
      mount = lib.mkOption {
        type = lib.types.str;
        default = "%r/secnix";
        description = "The mount point for the secrets. %r will be replaced with $XDG_RUNTIME_DIR";
      };
      defaultSymlinkPath = lib.mkOption {
        type = lib.types.str;
        default = "${config.xdg.configHome}/secnix/secrets";
        description = "The default path to symlink secrets";
      };
    };
  };

  config = lib.mkIf (cfg.secrets != {} || cfg.templates != {}) {
    assertions = [
      {
        assertion = cfg.sshKeys != [];
        message = "No ssh keys provided. No secrets will be able to be decrypted. Set config.secnix.sshKeys.";
      }
    ];
    systemd.user.services.secnix = lib.mkIf pkgs.stdenv.hostPlatform.isLinux {
      Unit = {
        Description = "Secnix activation";
      };
      Service = {
        Type = "oneshot";
        ExecStart = "${script}/bin/secnix-activation";
      };
      Install.WantedBy = ["default.target"];
    };

    home.activation.secnix = let
      systemctl = config.systemd.user.systemctlPath;
    in ''
      systemdStatus=$(${systemctl} --user is-system-running 2>&1 || true)
      if [ $systemdStatus = "running" ]; then
        $DRY_RUN_CMD ${systemctl} --user restart secnix
      else
        echo "Systemd is not running. Skipping secnix activation. If this is undesired, manually run ${script}/bin/secnix-activation"
      fi
      unset systemdStatus
    '';
  };
}
