# find-ecr-repository-action [![ts](https://github.com/int128/find-ecr-repository-action/actions/workflows/ts.yaml/badge.svg)](https://github.com/int128/find-ecr-repository-action/actions/workflows/ts.yaml)

## Getting Started

```yaml
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: int128/find-ecr-repository-action@v1
        with:
          repository-name: hello
```

## Specification

### Inputs

| Name                           | Default                    | Description                                             |
| ------------------------------ | -------------------------- | ------------------------------------------------------- |
| `repository-name`              | (required)                 | Name of the repository in Amazon ECR                    |
| `repository-not-found-message` | [action.yaml](action.yaml) | Error message to display if the repository is not found |

### Outputs

| Name             | Description                         |
| ---------------- | ----------------------------------- |
| `repository-uri` | URI of the repository in Amazon ECR |
