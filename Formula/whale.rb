class Whale < Formula
  desc "Native macOS VPN client with SwiftUI, routing rules, and Xray TUN"
  homepage "https://github.com/nagraver/vctl"
  url "https://github.com/nagraver/vctl/releases/download/v0.6.0/whale-0.6.0-macos-arm64.tar.gz"
  version "0.6.0"
  sha256 "1f9f442eb7a492344439b1bf72b12962a689ed4385aa26aecc58f6e8d2b89cd7"

  depends_on arch: :arm64
  depends_on macos: :ventura

  # Preserve the signed application bundle and its executable signatures intact.
  skip_clean "Whale.app"

  def install
    odie "VERSION does not match the formula" if (buildpath/"VERSION").read.strip != version.to_s
    bin.install "bin/whale"
    libexec.install "libexec/whale-helper", "libexec/xray"
    prefix.install "Whale.app"
    bash_completion.install "completions/whale.bash" => "whale"
    zsh_completion.install "completions/_whale"
    fish_completion.install "completions/whale.fish"
    pkgshare.install "licenses", "THIRD-PARTY-NOTICES.txt", "RELEASE.json", "XRAY_VERSION"
    doc.install "README.md", "DEVELOPMENT.md"
  end

  def caveats
    <<~EOS
      Open the native application:
        open "#{opt_prefix}/Whale.app"

      CLI commands: whale up, whale down, whale status.
      Settings remain in ~/.config/vctl, or WHALE_HOME when set.
      First connection requests macOS administrator approval to install the helper.
      After upgrading, open Settings and install the updated system helper.
      Before uninstalling, disconnect and choose Settings > Uninstall service.

      This Apple Silicon release is ad-hoc signed, not notarized by Apple.
    EOS
  end

  test do
    ENV["WHALE_HOME"] = (testpath/"profile").to_s
    assert_match version.to_s, shell_output("#{bin}/whale --version")
    assert_match version.to_s, shell_output("#{libexec}/whale-helper --version")
    snapshot = JSON.parse(shell_output("#{libexec}/whale-helper snapshot"))
    assert_equal 2, snapshot.fetch("protocol")
    assert_equal version.to_s, snapshot.fetch("version")
    assert_match "VPN:", shell_output("#{bin}/whale status")
    assert_match "Xray 26.9.9", shell_output("#{libexec}/xray version")
    assert_predicate libexec/"whale-helper", :executable?
    assert_predicate prefix/"Whale.app/Contents/MacOS/Whale", :executable?
    assert_predicate pkgshare/"licenses/xray/LICENSE", :file?
    refute_path_exists testpath/"profile"
    system "/usr/bin/codesign", "--verify", "--deep", "--strict", prefix/"Whale.app"
  end
end
