from __future__ import annotations

import shutil
import subprocess
from pathlib import Path
from typing import final, Final, Any
from collections.abc import Callable, Mapping

from pyk.kbuild.utils import k_version
from pyk.kdist.api import Target
from pyk.ktool.kompile import LLVMKompileType, PykBackend, kompile


PLUGIN_DIR: Final = Path(__file__).parent / "plugin"


def _find_boost_prefix() -> str | None:
    """Find boost include prefix, checking nix store and homebrew."""
    return _find_nix_or_brew(
        "boost",
        nix_pattern="*-boost-*-dev",
        check_subdir="include/boost/container_hash",
    )


def _find_nix_or_brew(
    name: str, *, nix_pattern: str | None = None, check_subdir: str = "include"
) -> str | None:
    """Find a library prefix in nix store or homebrew."""
    import glob

    if nix_pattern:
        for p in sorted(glob.glob(f"/nix/store/{nix_pattern}"), reverse=True):
            if (Path(p) / check_subdir).exists():
                return p
    for p in [f"/opt/homebrew/opt/{name}", f"/usr/local/opt/{name}"]:
        if (Path(p) / check_subdir).exists():
            return p
    return None


def _find_nix_prefix(pattern: str, check_subdir: str = "include") -> str | None:
    """Find a package prefix in the nix store."""
    import glob

    for p in sorted(glob.glob(f"/nix/store/{pattern}"), reverse=True):
        if (Path(p) / check_subdir).exists():
            return p
    return None


class SourceTarget(Target):
    SRC_DIR: Final = Path(__file__).parent

    def build(
        self,
        output_dir: Path,
        deps: dict[str, Path],
        args: dict[str, Any],
        verbose: bool,
    ) -> None:
        shutil.copytree(
            self.SRC_DIR / "script-semantics", output_dir / "script-semantics"
        )
        # Copy the plugin's krypto.md so `requires "plugin/krypto.md"` resolves
        plugin_out = output_dir / "plugin"
        plugin_out.mkdir(parents=True, exist_ok=True)
        shutil.copy(PLUGIN_DIR / "plugin" / "krypto.md", plugin_out / "krypto.md")

    def source(self) -> tuple[Path, ...]:
        return (self.SRC_DIR,)


class PluginTarget(Target):
    """Build the blockchain-k-plugin C++ crypto library (krypto.a)."""

    def build(
        self,
        output_dir: Path,
        deps: dict[str, Path],
        args: dict[str, Any],
        verbose: bool,
    ) -> None:
        import os
        import platform

        # Build inside a temporary copy so we don't pollute the source tree
        build_dir = output_dir / "_build"
        shutil.copytree(str(PLUGIN_DIR), str(build_dir), dirs_exist_ok=True)

        # Patch libff CMakeLists.txt for CMake 4.x compatibility
        libff_cmake = build_dir / "deps" / "libff" / "CMakeLists.txt"
        if libff_cmake.exists():
            text = libff_cmake.read_text()
            text = text.replace(
                "cmake_minimum_required(VERSION 2.8)",
                "cmake_minimum_required(VERSION 3.5)",
            )
            libff_cmake.write_text(text)

        # Remove stale CMake cache files copied from submodule
        for cache_file in build_dir.rglob("CMakeCache.txt"):
            cache_file.unlink()
        for cmake_files_dir in build_dir.rglob("CMakeFiles"):
            if cmake_files_dir.is_dir():
                shutil.rmtree(cmake_files_dir)

        env = dict(os.environ)
        # On macOS with Apple Silicon, disable ASM for libff
        if platform.machine() == "arm64":
            env["APPLE_SILICON"] = "true"

        make_args: list[str] = []
        # Find dependency prefixes (needed by K's LLVM backend headers and crypto libs)
        _prefixes = {
            "BOOST_PREFIX": _find_boost_prefix(),
            "GMP_PREFIX": _find_nix_or_brew("gmp", nix_pattern="*-gmp-*-dev"),
            "MPFR_PREFIX": _find_nix_or_brew("mpfr", nix_pattern="*-mpfr-*-dev"),
            "OPENSSL_PREFIX": _find_nix_or_brew(
                "openssl", nix_pattern="*-openssl-*-dev"
            ),
            "SECP256K1_PREFIX": _find_nix_prefix("*-secp256k1-[0-9]*"),
        }
        for var, val in _prefixes.items():
            if val:
                make_args.append(f"{var}={val}")

        make_cmd = ["make", "-C", str(build_dir), "-j8", "krypto", *make_args]
        if verbose:
            subprocess.run(make_cmd, check=True, env=env)
        else:
            subprocess.run(
                make_cmd,
                check=True,
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )

        # Copy the static library to the output dir
        krypto_a = build_dir / "build" / "krypto" / "lib" / "krypto.a"
        shutil.copy(str(krypto_a), str(output_dir / "krypto.a"))

        # Clean up the build directory
        shutil.rmtree(str(build_dir))

    def source(self) -> tuple[Path, ...]:
        return (PLUGIN_DIR,)


def _lib_ccopts(plugin_dir: Path) -> list[str]:
    """Compiler options needed to link the crypto plugin into the LLVM backend."""
    ccopts = ["-std=c++20"]
    ccopts += [str(plugin_dir / "krypto.a")]
    ccopts += ["-lssl", "-lcrypto", "-lsecp256k1"]

    # Add library search paths for nix/brew-installed dependencies
    openssl_lib = _find_nix_prefix("*-openssl-3*", check_subdir="lib/libssl.dylib")
    if not openssl_lib:
        openssl_lib = _find_nix_or_brew(
            "openssl", nix_pattern="*-openssl-3*", check_subdir="lib"
        )
    if openssl_lib:
        ccopts.insert(0, f"-L{Path(openssl_lib) / 'lib'}")
    secp_lib = _find_nix_prefix("*-secp256k1-[0-9]*", check_subdir="lib")
    if secp_lib:
        ccopts.insert(0, f"-L{Path(secp_lib) / 'lib'}")

    return ccopts


@final
class KompileTarget(Target):
    _kompile_args: Callable[[Path, Path], Mapping[str, Any]]

    def __init__(self, kompile_args: Callable[[Path, Path], Mapping[str, Any]]) -> None:
        self._kompile_args = kompile_args

    def build(
        self,
        output_dir: Path,
        deps: dict[str, Path],
        args: dict[str, Any],
        verbose: bool,
    ) -> None:
        kompile_args = self._kompile_args(
            deps["bitcoin-script-semantics.source"],
            deps["bitcoin-script-semantics.plugin"],
        )
        kompile(output_dir=output_dir, verbose=verbose, **kompile_args)

    def context(self) -> dict[str, str]:
        return {"k-version": k_version().text}

    def deps(self) -> tuple[str, ...]:
        return (
            "bitcoin-script-semantics.source",
            "bitcoin-script-semantics.plugin",
        )


@final
class HaskellKompileTarget(Target):
    """Haskell backend target for K proofs (kprove).

    Builds both a Haskell definition and an LLVM library so that the
    kore-rpc-booster can delegate concrete hook evaluations (SHA256,
    RIPEMD160, ECDSA) to the LLVM backend during proofs.
    """

    def build(
        self,
        output_dir: Path,
        deps: dict[str, Path],
        args: dict[str, Any],
        verbose: bool,
    ) -> None:
        src_dir = deps["bitcoin-script-semantics.source"]
        plugin_dir = deps["bitcoin-script-semantics.plugin"]

        # Build Haskell definition
        kompile(
            output_dir=output_dir,
            verbose=verbose,
            backend=PykBackend.HASKELL,
            main_file=src_dir / "script-semantics/script-verification.k",
            main_module="SCRIPT-VERIFICATION",
            syntax_module="SCRIPT-VERIFICATION",
            include_dirs=(src_dir,),
            hook_namespaces=("KRYPTO",),
            warnings_to_errors=True,
        )

        # Build LLVM library for concrete hook evaluation during proofs
        kompile(
            output_dir=output_dir / "llvm-library",
            verbose=verbose,
            backend=PykBackend.LLVM,
            main_file=src_dir / "script-semantics/script-verification.k",
            main_module="SCRIPT-VERIFICATION",
            syntax_module="SCRIPT-VERIFICATION",
            include_dirs=(src_dir,),
            hook_namespaces=("KRYPTO",),
            ccopts=_lib_ccopts(plugin_dir),
            llvm_kompile_type=LLVMKompileType.C,
            warnings_to_errors=True,
            opt_level=3,
        )

    def context(self) -> dict[str, str]:
        return {"k-version": k_version().text}

    def deps(self) -> tuple[str, ...]:
        return (
            "bitcoin-script-semantics.source",
            "bitcoin-script-semantics.plugin",
        )


__TARGETS__: Final = {
    "source": SourceTarget(),
    "plugin": PluginTarget(),
    "llvm": KompileTarget(
        lambda src_dir, plugin_dir: {
            "backend": PykBackend.LLVM,
            "main_file": src_dir / "script-semantics/script.k",
            "include_dirs": (src_dir,),
            "hook_namespaces": ("KRYPTO",),
            "ccopts": _lib_ccopts(plugin_dir),
            "warnings_to_errors": True,
            "gen_glr_bison_parser": True,
            "opt_level": 3,
        },
    ),
    "llvm-lib": KompileTarget(
        lambda src_dir, plugin_dir: {
            "backend": PykBackend.LLVM,
            "main_file": src_dir / "script-semantics/script.k",
            "include_dirs": (src_dir,),
            "hook_namespaces": ("KRYPTO",),
            "ccopts": _lib_ccopts(plugin_dir),
            "llvm_kompile_type": LLVMKompileType.C,
            "warnings_to_errors": True,
            "opt_level": 3,
        },
    ),
    "haskell": HaskellKompileTarget(),
}
