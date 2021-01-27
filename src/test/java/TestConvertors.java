import burp.AES;
import org.junit.jupiter.api.Test;
import org.python.core.Py;
import org.python.core.PySystemState;
import org.python.util.PythonInterpreter;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;

public class TestConvertors {
    @Test
    void Python(){
        assertDoesNotThrow(()->{
            String code = "import sys\n" +
                    "path = \"/Users/ahao/git/python2/venv/lib/python2.7/site-packages\"\n" +
                    "sys.path.append(path)\n" +
                    "print sys.path"+
//                "import requests\n" +
//                "print requests.get('https://www.baidu.com').text\n" +
                    "";

            PySystemState systemState = Py.getSystemState();
            systemState.path.add("/Users/ahao/git/python2/venv/lib/python2.7/site-packages");
            PythonInterpreter pythonInterpreter = new PythonInterpreter();
            pythonInterpreter.getSystemState();
//            pythonInterpreter.exec(code);

            code = "import requests\n" +
                    "print requests.get('http://www.baidu.com').content\n" +
                    "";
            pythonInterpreter.exec(code);
        });
    }

    @Test
    void AesKey() throws Exception {

        assertDoesNotThrow(() -> {
            String encrypt = AES.encrypt("encrypt", "123456", 32, "AES/ECB/PKCS5Padding", "");
            System.out.println("encrypt = " + encrypt);

            encrypt = AES.encrypt("encrypt", "12345678901234567890", 16, "AES/ECB/PKCS5Padding", "");
            System.out.println("encrypt = " + encrypt);

        });

        assertThrows(Exception.class, () -> {
            String encrypt = AES.encrypt("encrypt", "123456", -32, "AES/ECB/PKCS5Padding", "");
            System.out.println("encrypt = " + encrypt);
        });

        assertThrows(Exception.class, () -> {
            String encrypt = AES.encrypt("encrypt", "12345678901234567890", 15, "AES/ECB/PKCS5Padding", "");
            System.out.println("encrypt = " + encrypt);
        });
    }
}
