import burp.Convertors;
import org.junit.jupiter.api.Test;
import org.python.core.Py;
import org.python.core.PySystemState;
import org.python.util.PythonInterpreter;

import java.util.HashMap;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

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
                    "print requests.get('http://www.baidu.com').content\n"+
                    "";
            pythonInterpreter.exec(code);
        });
    }
}
