{
  lib,
  python3,
  iproute2,
  iptables,
  nftables,
  conntrack-tools,
  tcpdump,
  openssl,
  fetchFromGitHub,
  makeWrapper,
  python3Packages,
}:

python3Packages.buildPythonPackage (finalAttrs: {
  pname = "trustfall";
  version = "main";
  src = fetchFromGitHub {
    owner = "rohanssrao";
    repo = "trustfall";
    rev = finalAttrs.version;
    hash = "sha256-DYzDFofcaA3D4OAlHg8wGoXAs9dG6o0uX5RtXFnfZKU=";
  };

  pyproject = true;
  __structuredAttrs = true;
  doCheck = false; # skip any pytest tests

  nativeBuildInputs = [
    makeWrapper
  ];

  buildInputs = [
    python3
    iproute2
    iptables
    nftables
    conntrack-tools
    tcpdump
    openssl
  ];

  propagatedBuildInputs = with python3Packages; [
    cryptography
    scapy
    textual
    pyopenssl
    hatchling
  ];

  installPhase = ''
    mkdir -p $out/bin
    makeWrapper ${lib.getExe python3} $out/bin/trustfall \
      --set PYTHONPATH $PYTHONPATH \
      --add-flags "-m" \
      --add-flags "trustfall.cli"
  '';

  meta = {
    description = "Transparent MitM harness for sniffing and breaking TLS over a network.";
    homepage = "https://github.com/rohanssrao/trustfall";
    license = lib.licenses.gpl3;
    maintainers = with lib.maintainers; [
      rohanssrao
    ];
    sourceProvenance = with lib.sourceTypes; [ fromSource ];
  };

})
