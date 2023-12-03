{ stdenv
, fetchFromGitHub
, fmt_9
, mbedtls_2
}:
let
  project_ctr_src = fetchFromGitHub {
    owner = "justinkb";
    repo = "Project_CTR";
    rev = "b27372779715a27d28f746d77af7f246060b9cd8";
    hash = "sha256-DsRxWgCsxFxg6OUerNuDhJnyjOi7xKzcb56Ms8/Lmis=";
  };

  libtoolchain = stdenv.mkDerivation {
    pname = "libtoolchain";
    version = "unstable";

    src = "${project_ctr_src}/ctrtool/deps/libtoolchain";

    buildInputs = [
      fmt_9.dev
      mbedtls_2
    ];

    buildPhase = ''
      sed -i '/PROJECT_DEPEND_LOCAL_DIR =/d' makefile
      make shared_lib
    '';

    installPhase = ''
      mkdir -p $out/lib
      cp bin/libtoolchain.so.0.5.0 $out/lib
      ln -s $out/lib/libtoolchain.so{.0.5.0,.0}
      ln -s $out/lib/libtoolchain.so{.0,}
      cp -a include $out
    '';
  };

  libbroadon-es = stdenv.mkDerivation {
    pname = "libbroadon-es";
    version = "unstable";

    src = "${project_ctr_src}/ctrtool/deps/libbroadon-es";

    buildInputs = [
      libtoolchain
    ];

    buildPhase = ''
      sed -i '/PROJECT_DEPEND_LOCAL_DIR =/d' makefile
      make shared_lib
    '';

    installPhase = ''
      mkdir -p $out/lib
      cp bin/libbroadon-es.so.0.1.0 $out/lib
      ln -s $out/lib/libbroadon-es.so{.0.1.0,.0}
      ln -s $out/lib/libbroadon-es.so{.0,}
      cp -a include $out
    '';
  };

  libnintendo-n3ds = stdenv.mkDerivation {
    pname = "libnintendo-n3ds";
    version = "unstable";

    src = "${project_ctr_src}/ctrtool/deps/libnintendo-n3ds";

    buildInputs = [
      libtoolchain
      libbroadon-es
      fmt_9.dev
    ];

    buildPhase = ''
      sed -i '/PROJECT_DEPEND_LOCAL_DIR =/d' makefile
      make shared_lib
    '';

    installPhase = ''
      mkdir -p $out/lib
      cp bin/libnintendo-n3ds.so.0.1.0 $out/lib
      ln -s $out/lib/libnintendo-n3ds.so{.0.1.0,.0}
      ln -s $out/lib/libnintendo-n3ds.so{.0,}
      cp -a include $out
    '';
  };
in
stdenv.mkDerivation {
  pname = "ctrtool";
  version = "1.2.0";

  src = "${project_ctr_src}/ctrtool";

  buildInputs = [
    libnintendo-n3ds
    libbroadon-es
    libtoolchain
    mbedtls_2
    fmt_9.dev
  ];

  buildPhase = ''
    sed -i 's/toolchain mbedtls fmt/toolchain mbedcrypto fmt/' makefile
    sed -i '/PROJECT_DEPEND_LOCAL_DIR =/d' makefile
    make
  '';

  installPhase = ''
    mkdir -p $out/bin
    cp bin/ctrtool $out/bin
  '';
}
