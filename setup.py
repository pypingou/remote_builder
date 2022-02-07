from setuptools import setup


setup(
    name="remote_builder",
    version="0.0.1",
    description="A simple server/client RPC program to easily do RPM build remotely",
    # Possible options are at https://pypi.python.org/pypi?%3Aaction=list_classifiers
    classifiers=[
        "Development Status :: 3 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: BSD License",
        "Operating System :: POSIX :: Linux",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Topic :: Software Development :: Build Tools",
    ],
    license="BSD",
    maintainer="Pierre-Yves Chibon",
    maintainer_email="pingou@pingoured.fr",
    platforms=["Fedora", "CentOS-Stream", "GNU/Linux"],
    url="https://github.com/pypingou/remote_builder",
    packages=["remote_builder", "remote_builder.server", "remote_builder.cli"],
    include_package_data=True,
    package_data={},
    zip_safe=False,
    install_requires=["rpyc"],
    entry_points={
        "console_scripts": [
            "remote_builder_server = remote_builder.server.server:main",
            "remote_builder = remote_builder.cli.cli:main",
        ]
    },
)
