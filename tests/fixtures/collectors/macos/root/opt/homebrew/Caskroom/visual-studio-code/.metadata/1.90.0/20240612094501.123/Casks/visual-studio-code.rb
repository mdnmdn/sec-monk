cask "visual-studio-code" do
  version "1.90.0"
  sha256 :no_check
  url "https://update.code.visualstudio.com/#{version}/darwin-arm64/stable"
  name "Microsoft Visual Studio Code"
  homepage "https://code.visualstudio.com/"
  app "Visual Studio Code.app"
end
