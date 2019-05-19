<!-- TITLE: Java -->
<!-- SUBTITLE: A quick summary of Java -->

# Compiling
# Java

We start with a `src` directory, finding the *.java file and verify it's path.

### Adding Build Dependencies

	javac -cp "./commons-codec-1.12/commons-codec-1.12.jar" app/path/to/Main.java

### Build Jar and MINIFEST

	jar -cvfe App.jar Main app/path/to/