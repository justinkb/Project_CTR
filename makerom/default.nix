{ stdenv
, fetchFromGitHub
, mbedtls_2
, libyaml
}:
let
  project_ctr_src = fetchFromGitHub {
    owner = "justinkb";
    repo = "Project_CTR";
    rev = "b27372779715a27d28f746d77af7f246060b9cd8";
    hash = "sha256-DsRxWgCsxFxg6OUerNuDhJnyjOi7xKzcb56Ms8/Lmis=";
  };

  libblz = stdenv.mkDerivation {
    pname = "libblz";
    version = "unstable";

    src = "${project_ctr_src}/makerom/deps/libblz";

    buildPhase = ''
      sed -i '/PROJECT_DEPEND_LOCAL_DIR =/d' makefile
      make shared_lib
    '';

    installPhase = ''
      mkdir -p $out/lib
      cp bin/libblz.so.0.1.0 $out/lib
      ln -s $out/lib/libblz.so{.0.1.0,.0}
      ln -s $out/lib/libblz.so{.0,}
      cp -a include $out
    '';
  };
in
stdenv.mkDerivation {
  pname = "makerom";
  version = "0.18.4";

  src = "${project_ctr_src}/makerom";

  buildInputs = [
    libblz
    mbedtls_2
    libyaml.dev
  ];

  buildPhase = ''
    sed -i 's/<libyaml\/yaml.h>/<yaml.h>/' src/yaml_parser.h
    sed -i 's/PROJECT_DEPEND = mbedtls/PROJECT_DEPEND = mbedcrypto/' makefile
    sed -i '/PROJECT_DEPEND_LOCAL_DIR =/d' makefile
    make
  '';

  installPhase = ''
    mkdir -p $out/bin
    cp bin/makerom $out/bin
  '';
}
