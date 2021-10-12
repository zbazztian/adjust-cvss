# adjust-cvss

Takes a SARIF file and a list of query id patterns as input and assigns custom [cvss scores](https://github.blog/changelog/2021-07-19-codeql-code-scanning-new-severity-levels-for-security-alerts/) (aka `security-severity`) to those queries. This allows to make specific queries less or more severe, which affects how they are displayed (`Low`, `High`, `Critical`, ...) and whether they cause pull request checks to fail.

# Example

The following example sets the cvss score of all queries to `1.2` except for the query with the id `java/xss`. Note that this only affects queries with a `security-severity` metadata field. Therefore, most code quality related queries are not affected:

```yaml
name: "CodeQL"

on:
  push:
    branches: [ master ]
  pull_request:
    branches: [ master ]

jobs:
  analyze:
    name: Analyze
    runs-on: ubuntu-latest
    permissions:
      actions: read
      contents: read
      security-events: write

    strategy:
      fail-fast: false
      matrix:
        language: [ 'java' ]

    steps:
    - name: Checkout repository
      uses: actions/checkout@v2

    - name: Initialize CodeQL
      uses: github/codeql-action/init@v1
      with:
        languages: ${{ matrix.language }}
        queries: security-and-quality

    - run: |
        javatest/build

    - name: Perform CodeQL Analysis
      uses: github/codeql-action/analyze@v1
      with:
        output: sarif-results
        upload: False

    - name: adjust-cvss
      uses: zbazztian/adjust-cvss@master
      with:
        patterns: |
          **:1.2
          java/xss:9.9
        input: sarif-results/${{ matrix.language }}.sarif
        output: sarif-results/${{ matrix.language }}.sarif

    - name: Upload SARIF
      uses: github/codeql-action/upload-sarif@v1
      with:
        sarif_file: sarif-results/${{ matrix.language }}.sarif
```

Note how we provided `upload: False` and `output: sarif-results` to the `analyze` action. That way we can filter the SARIF with the `adjust-cvss` action before uploading it via `upload-sarif`.

# Patterns

Each pattern line is of the form:
```
<id pattern>:<score pattern>
```

for example:
```
**:1.2                           # all queries shall have a cvss of `1.2`.
java/xss:9.9                     # the Java XSS query should have a score of `9.9`
java/**:5.4                      # all Java queries have a score of `5.4`
```
