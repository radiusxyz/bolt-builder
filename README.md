
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

To run the tests and get detailed output, use the following command:

```bash
go test -run TestAccessListExclusionConstraints ./builder -v
```

* **`-v` flag**: The `-v` flag stands for **verbose**. It ensures that Go tests output detailed information about each test case, including whether the tests passed or failed, along with additional debugging information.

* **`-run` flag**: This flag is used to specify a particular test or test pattern to run. In this case, `TestAccessListExclusionConstraints` is the name of the test function you want to run.

* **Test Directory**: The `./builder` specifies the path to the package that contains the tests. If your tests are located in a different package or directory, you can adjust the path accordingly.

### 3. **View Detailed Test Output**

Running the above command will display detailed logs for each test case. For example:

```bash
=== RUN   TestAccessListExclusionConstraints
--- PASS: TestAccessListExclusionConstraints (0.00s)
PASS
ok      ./builder   0.001s
```

If there are any issues with the test, the output will display failure messages and relevant logs to help you debug the issue.
