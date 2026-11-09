class Whale < Formula
  desc "macOS CLI VPN client with subscriptions, routing rules, and native Xray TUN"
  homepage "https://github.com/nagraver/vctl"
  url "https://github.com/nagraver/vctl.git",
      tag: "v0.5.0",
      revision: "bebbf804fd6400aaddc84256ddfa533594c160a8"
  version "0.5.0"

  depends_on :macos
  depends_on "go" => :build

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
    odie "VERSION does not match the formula" unless (buildpath/"VERSION").read.strip == version.to_s
    system "go", "build", "-trimpath", "-ldflags", "-s -w -X github.com/nagraver/vctl/internal/whale.Version=#{version}", "-o", bin/"whale", "./cmd/whale"
    resource("xray").stage do
      libexec.install "xray"
      (libexec/"xray").chmod 0755
    end
    generate_completions_from_executable(bin/"whale", "completion", shells: [:bash, :zsh, :fish])
  end

  def caveats
    <<~EOS
      Settings are stored in ~/.config/vctl, or in WHALE_HOME when set.
      TUN: whale tun up (launchd; requests sudo). Stop it before upgrading.
      Before uninstalling the package, run whale tun uninstall to remove its system service.
      zsh completion is installed automatically; configure Homebrew shellenv
      before compinit or Oh My Zsh to enable it.
    EOS
  end

  test do
    ENV["WHALE_HOME"] = (testpath/"profile").to_s
    assert_match version.to_s, shell_output("#{bin}/whale --version")
    assert_match "Selected: auto", shell_output("#{bin}/whale nodes")
    assert_match "whale", shell_output("#{bin}/whale completion zsh")
    assert_match "Xray 26.9.9", shell_output("#{libexec}/xray version")
    assert_predicate testpath/"profile", :directory?
    refute_path_exists testpath/"profile/state.json"
  end
end
