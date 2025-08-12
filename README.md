
## How it works

The builder has the standard functionality of the Flashbots builder, but with the
added functionality of the Constraints API which can be summarized as follows:

1. The builder subscribes to the relays for streams of constraints sent by proposers.
2. After receiving constraints and validating their authenticity, the builder builds a block that
   respects all constraints and includes the necessary proofs of inclusion in its bid.
3. The builder sends the signed bid as usual to the relay.

## Go Installation and Setup Guide

To build this project, you need to have Go 1.22 installed. Follow the steps below to install Go 1.22 and set up your development environment.

### 1. Install Go Using GVM (Go Version Manager)

If you want to manage multiple versions of Go easily, you can use `gvm`.

1. **Install GVM**:

   Run the following command to install GVM (Go Version Manager):

   ```bash
   bash < <(curl -s -S -L https://raw.githubusercontent.com/moovweb/gvm/master/binscripts/gvm-installer)
   ```

2. **Source GVM script**:

   After installation, run:

   ```bash
   source ~/.gvm/scripts/gvm
   ```

3. **Verify GVM installation**:

   You can check if GVM is installed correctly by running:

   ```bash
   gvm version
   ```

4. **Install Go 1.22**:

   After setting up GVM, install Go 1.22 with the following command:

   ```bash
   gvm install go1.22
   gvm use go1.22 --default
   ```

5. **Verify Go installation**:

   Check the installed Go version by running:

   ```bash
   go version
   ```

### 2. **Running Tests with Detailed Output**

Once Go is installed and set up, you can run the tests to ensure everything is working as expected.

To run the Bolt commitment tests and get detailed output, use the following commands:

#### Running Exclusion Commitment Tests

```bash
go test -run TestExclusionCommitment ./builder -v
```

#### Running Inclusion Commitment Tests

```bash
go test -run TestInclusionCommitment ./builder -v
```

#### Test List

```bash
go test -run TestInclusionCommitment ./builder -v
go test -run TestExclusionCommitment ./builder -v
go test -run TestSubscribeProposerConstraints ./builder -v
go test -run TestExclusionConstraintFiltering ./miner -v
go test -run TestInclusionConstraintDynamicDetection ./miner -v
go test -run TestAlgorithmSelection ./miner -v
go test -run TestMainLoopInclusionExclusionConstraints ./miner -v
```

* **`-v` flag**: The `-v` flag stands for **verbose**. It ensures that Go tests output detailed information about each test case, including whether the tests passed or failed, along with additional debugging information about StateScope validation and constraint processing.

* **`-run` flag**: This flag is used to specify a particular test or test pattern to run. In this case, `TestExclusionCommitment` and `TestInclusionCommitment` are the test functions for Bolt protocol commitment scenarios.

* **Test Directory**: The `./builder` specifies the path to the package that contains the tests. If your tests are located in a different package or directory, you can adjust the path accordingly.

### 3. **Test Coverage**

These tests cover the following protocol commitment scenarios:

- **Exclusion Commitment**: Tests the filtering of conflicting transactions based on StateScope address conflicts
- **Inclusion Commitment**: Tests the inclusion of winning transactions through constraint cache mechanisms
