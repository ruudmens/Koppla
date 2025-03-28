from setuptools import setup, find_packages

setup(
    name="koppla",
    version="0.16",
    packages=find_packages(),
    install_requires=[
        "ldap3",
        "mcp",
        "python-dotenv",
        "cryptography",
    ],
    entry_points={
        "console_scripts": [
            "koppla=koppla.server:mcp.run",
            "koppla-config=koppla.cli:config_command",
        ]
    },
    author="Rudy Mens - LazyAdmin.nl",
    description="Koppla - Active Directory MCP Server",
    long_description=open("README.md", encoding="utf-8").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/ruudmens/koppla",
    license="MIT"
)