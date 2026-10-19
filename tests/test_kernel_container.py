import os
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest import mock

from syzrun.builder.container import ContainerBuild, HOST_MAKE_VARIABLES
from syzrun.builder.kernel import KernelBuilder
from syzrun.builder.toolchain import ToolchainError


class KernelContainerTests(unittest.TestCase):
    def test_profile_image_overrides_environment(self):
        with mock.patch.dict(os.environ, {"PLATFORM_KERNEL_BUILD_IMAGE": "default:v2"}):
            container = ContainerBuild.from_environment({}, image="special:v1")
        self.assertEqual(container.image, "special:v1")

    def test_make_requires_container(self):
        for image in ("", "syzrun-kernel-build:v1"):
            with self.subTest(image=image):
                builder = KernelBuilder.__new__(KernelBuilder)
                builder.toolchain = SimpleNamespace(
                    root=Path('/tmp/toolchains/gcc-8.0.1'),
                    library_dir=Path('/tmp/toolchains/gcc-8.0.1/lib'),
                )
                builder.timeout = 10
                builder.runtime_profile = SimpleNamespace(build_env={"CUSTOM_FLAG": "yes"})
                cwd = Path('/tmp/case/kernel/linux')
                args = ['make', 'ARCH=x86_64', 'bzImage']
                env = {"PATH": "/host/conda/bin", "LD_LIBRARY_PATH": "/host/lib"}
                with mock.patch.dict(os.environ, {"PLATFORM_KERNEL_BUILD_IMAGE": image}):
                    with mock.patch('syzrun.builder.kernel.run') as run:
                        if not image:
                            with self.assertRaisesRegex(ToolchainError, "PLATFORM_KERNEL_BUILD_IMAGE"):
                                builder._run_make(args, cwd=cwd, env=env, timeout=10, log_path=Path("/tmp/build.log"))
                            run.assert_not_called()
                            continue
                        builder._run_make(args, cwd=cwd, env=env, timeout=10,
                                          log_path=Path('/tmp/build.log'))
                actual = run.call_args.args[0]
                if not image:
                    self.assertEqual(actual, args)
                else:
                    self.assertEqual(actual[:3], ['docker', 'run', '--rm'])
                    self.assertEqual(actual[-(4 + len(HOST_MAKE_VARIABLES)):], [image, *args, *HOST_MAKE_VARIABLES])
                    self.assertIn(f'{cwd}:{cwd}', actual)
                    self.assertIn('/tmp/toolchains/gcc-8.0.1:/tmp/toolchains/gcc-8.0.1:ro', actual)
                    self.assertIn('CUSTOM_FLAG=yes', actual)
                    self.assertNotIn('PATH=/host/conda/bin', actual)
                    self.assertNotIn('LD_LIBRARY_PATH=/host/lib', actual)
                self.assertEqual(run.call_args.kwargs['timeout'], 10)
