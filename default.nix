{ pkgs ? import <nixpkgs> {} }:
let
  stdenv = pkgs.overrideCC pkgs.stdenv pkgs.clang_6;
in rec {
  enableDebugging = false; #true;

  lwi = stdenv.mkDerivation {
    name = "lwi";
    dontStrip = enableDebugging;
    IS_DEV = enableDebugging;
    srcs = [./src ./ac];
    sourceRoot = "src";
    buildInputs = [
      pkgs.cmake
    ];
    #cmakeFlags = [
      #"-DCMAKE_BUILD_TYPE=Debug"
    #];
    enableParallelBuilding = true;
  };
}
