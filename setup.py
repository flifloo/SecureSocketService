from setuptools import setup, find_packages


def readme():
    with open('README.md') as f:
        return f.read()


setup(name="SecureSocketService",
      version="1.0.1",
      description="A socket service with secure connexion",
      long_description=readme(),
      classifiers=[
            'Development Status :: 3 - Alpha',
            'License :: OSI Approved :: MIT License',
            'Programming Language :: Python :: 3.7',
            'Topic :: System :: Networking',
      ],
      url="https://github.com/flifloo/SecureSocketService",
      author="flifloo",
      author_email="flifloo@gmail.com",
      license="MIT",
      packages=find_packages(),
      install_requires=[
            'cryptography',
      ],
      zip_safe=False)
