class Vctl < Formula
  desc "macOS CLI VPN client with subscriptions, routing rules, and native Xray TUN"
  homepage "https://github.com/nagraver/vctl"
  url "https://github.com/nagraver/vctl.git",
      revision: "d584cd5fce8bb275dd7e1c58c06e57030b16e783"
  version "0.2.0"

  depends_on :macos
  depends_on "python@3.14"

  on_arm do
    resource "xray" do
      url "https://github.com/XTLS/Xray-core/releases/download/v26.9.9/Xray-macos-arm64-v8a.zip"
      sha256 "b7cf765d60ccc703853d4218c49a1eacc5bca764543b9540bdeaf45c951afc7d"
    end
  end

  on_intel do
    resource "xray" do
      url "https://github.com/XTLS/Xray-core/releases/download/v26.9.9/Xray-macos-64.zip"
      sha256 "32b5d106b9936f3ae2044cd283d9e22749b57fd30b34a58792b86c90018bb5e4"
    end
  end

  def install
    # The application uses only Python's standard library. Keep its source layout
    # intact: privileged entry points and supervisors run from this directory.
    libexec.install "vctl", "vless_client"
    resource("xray").stage do
      (libexec/".tools").install "xray"
      (libexec/".tools/xray").chmod 0755
    end
    zsh_completion.install libexec/"vless_client/completions/_vctl"
    (bin/"vctl").write <<~SH
      #!/bin/sh
      export VCTL_HOME="${VCTL_HOME:-$HOME/.config/vctl}"
      exec "#{Formula["python@3.14"].opt_bin}/python3.14" "#{libexec}/vctl" "$@"
    SH
    (bin/"vctl").chmod 0755
  end

  def caveats
    <<~EOS
      Settings are stored in ~/.config/vctl, or in VCTL_HOME when set.
      TUN: vctl tun start (requests sudo). Stop it before upgrading/uninstalling.
      zsh completion is installed automatically; configure Homebrew shellenv
      before compinit or Oh My Zsh to enable it.
    EOS
  end

  test do
    ENV["VCTL_HOME"] = (testpath/"profile").to_s
    assert_match "Selected: auto", shell_output("#{bin}/vctl nodes")
    assert_match "#compdef vctl", shell_output("#{bin}/vctl completion zsh")
    assert_match "Xray 26.9.9", shell_output("#{libexec}/.tools/xray version")
    assert_predicate testpath/"profile", :directory?
    refute_path_exists testpath/"profile/state.json"
  end
end
