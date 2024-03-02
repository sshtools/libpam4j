module org.jvnet.libpam {
	requires transitive com.sun.jna;
	requires java.logging;
	exports org.jvnet.libpam;
	exports org.jvnet.libpam.impl to com.sun.jna;
}