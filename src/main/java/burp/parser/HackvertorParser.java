/* HackvertorParser.java */
/* Generated By:JavaCC: Do not edit this line. HackvertorParser.java */
package burp.parser;

import java.io.StringReader;
import java.util.LinkedList;
import java.util.ArrayList;
import org.unbescape.java.JavaEscape;

public class HackvertorParser implements HackvertorParserConstants {

    private static String getTokenText(Token first, Token cur) {
    Token t;
    StringBuffer sb = new StringBuffer();

    for (t=first; t != cur.next; t = t.next) {
      if (t.specialToken != null) {
        Token tt=t.specialToken;
        while (tt.specialToken != null)
          tt = tt.specialToken;
        for (; tt != null; tt = tt.next)
          sb.append(tt.image);
      };
      sb.append(t.image);
    };
    return sb.toString();
    }

    public static LinkedList<Element> parse(String string) throws ParseException {
        HackvertorParser parser = new HackvertorParser(new StringReader(string));
        LinkedList<Element> elementList = parser.Input();
//        for (Element e : elementList) {
//            System.out.println(e.getClass() + " - " + e.toString());
//        }
        return elementList;
    }

  final public LinkedList<Element> Input() throws ParseException {LinkedList<Element> s = new LinkedList<Element>();
    LinkedList<Element> e;
    label_1:
    while (true) {
      switch ((jj_ntk==-1)?jj_ntk_f():jj_ntk) {
      case TAG_START:
      case ENDTAG_START:
      case TEXT:
      case LESSTHAN:
      case ST_ERR:
      case SELF_CLOSE_TAG_END:
      case TAG_END:
      case IT_ERR:
      case QUOTED_STRING_VAL:
      case LITERAL_VAL:
      case COMMA:
      case ARGS_END:
      case ARG_ERR:{
        ;
        break;
        }
      default:
        jj_la1[0] = jj_gen;
        break label_1;
      }
      e = ElementSequence();
s.addAll(e);
    }
    jj_consume_token(0);
{if ("" != null) return s;}
    throw new Error("Missing return statement in function");
}

  final public LinkedList<Element> ElementSequence() throws ParseException {LinkedList<Element> elements = new LinkedList<Element>();
 Element e;
 Token text;
 Token firstToken = getToken(1);
    try {
      switch ((jj_ntk==-1)?jj_ntk_f():jj_ntk) {
      case TAG_START:{
        elements = StartTag();
{if ("" != null) return elements;}
        break;
        }
      case ENDTAG_START:{
        elements = CloseTag();
{if ("" != null) return elements;}
        break;
        }
      case LESSTHAN:{
        jj_consume_token(LESSTHAN);
elements.add(new Element.TextElement("<")); {if ("" != null) return elements;}
        break;
        }
      case TEXT:
      case ST_ERR:
      case SELF_CLOSE_TAG_END:
      case TAG_END:
      case IT_ERR:
      case QUOTED_STRING_VAL:
      case LITERAL_VAL:
      case COMMA:
      case ARGS_END:
      case ARG_ERR:{
        switch ((jj_ntk==-1)?jj_ntk_f():jj_ntk) {
        case TEXT:{
          text = jj_consume_token(TEXT);
          break;
          }
        case ST_ERR:{
          text = jj_consume_token(ST_ERR);
          break;
          }
        case IT_ERR:{
          text = jj_consume_token(IT_ERR);
          break;
          }
        case ARG_ERR:{
          text = jj_consume_token(ARG_ERR);
          break;
          }
        case QUOTED_STRING_VAL:{
          text = jj_consume_token(QUOTED_STRING_VAL);
          break;
          }
        case LITERAL_VAL:{
          text = jj_consume_token(LITERAL_VAL);
          break;
          }
        case COMMA:{
          text = jj_consume_token(COMMA);
          break;
          }
        case ARGS_END:{
          text = jj_consume_token(ARGS_END);
          break;
          }
        case TAG_END:{
          text = jj_consume_token(TAG_END);
          break;
          }
        case SELF_CLOSE_TAG_END:{
          text = jj_consume_token(SELF_CLOSE_TAG_END);
          break;
          }
        default:
          jj_la1[1] = jj_gen;
          jj_consume_token(-1);
          throw new ParseException();
        }
elements.add(new Element.TextElement(text.image)); {if ("" != null) return elements;}
        break;
        }
      default:
        jj_la1[2] = jj_gen;
        jj_consume_token(-1);
        throw new ParseException();
      }
    } catch (ParseException ex) {
//Catch any unexpected inputs including EOF and try to recover
        token_source.SwitchTo(DEFAULT);
        elements.addFirst(new Element.TextElement(getTokenText(firstToken, getToken(0))));
        elements.addAll(ElementSequence());
        {if ("" != null) return elements;}
    }
    throw new Error("Missing return statement in function");
}

  final public LinkedList<Element> StartTag() throws ParseException {LinkedList<Element> elements = new LinkedList<Element>();
    ArrayList<String> args = new ArrayList<String>();
    LinkedList<Element> rest = null;
    Token t;
    Token identifier = null;
    String arg;
    Token firstToken = getToken(1);
    try {
      t = jj_consume_token(TAG_START);
      identifier = jj_consume_token(FUNCTION_NAME);
      switch ((jj_ntk==-1)?jj_ntk_f():jj_ntk) {
      case ARGS_START:{
        jj_consume_token(ARGS_START);
        switch ((jj_ntk==-1)?jj_ntk_f():jj_ntk) {
        case QUOTED_STRING_VAL:
        case LITERAL_VAL:{
          arg = Argument();
args.add(arg);
          label_2:
          while (true) {
            switch ((jj_ntk==-1)?jj_ntk_f():jj_ntk) {
            case COMMA:{
              ;
              break;
              }
            default:
              jj_la1[3] = jj_gen;
              break label_2;
            }
            jj_consume_token(COMMA);
            arg = Argument();
args.add(arg);
          }
          break;
          }
        default:
          jj_la1[4] = jj_gen;
          ;
        }
        jj_consume_token(ARGS_END);
        break;
        }
      default:
        jj_la1[5] = jj_gen;
        ;
      }
      switch ((jj_ntk==-1)?jj_ntk_f():jj_ntk) {
      case TAG_END:{
        jj_consume_token(TAG_END);
elements.add(new Element.StartTag(identifier.image, args)); {if ("" != null) return elements;}
        break;
        }
      case SELF_CLOSE_TAG_END:
      case SELF_CLOSE_TAG_END_AT:{
        switch ((jj_ntk==-1)?jj_ntk_f():jj_ntk) {
        case SELF_CLOSE_TAG_END:{
          jj_consume_token(SELF_CLOSE_TAG_END);
          break;
          }
        case SELF_CLOSE_TAG_END_AT:{
          jj_consume_token(SELF_CLOSE_TAG_END_AT);
          break;
          }
        default:
          jj_la1[6] = jj_gen;
          jj_consume_token(-1);
          throw new ParseException();
        }
elements.add(new Element.SelfClosingTag(identifier.image, args)); {if ("" != null) return elements;}
        break;
        }
      default:
        jj_la1[7] = jj_gen;
        jj_consume_token(-1);
        throw new ParseException();
      }
    } catch (ParseException e) {
//        System.out.println("Failed Start tag. Treating as text");
        elements.addFirst(new Element.TextElement(getTokenText(firstToken, getToken(0))));
    }
    if (jj_2_1(2)) {
      rest = ElementSequence();
    } else {
      ;
    }
if(rest != null) elements.addAll(rest); {if ("" != null) return elements;}
    throw new Error("Missing return statement in function");
}

  final public String Argument() throws ParseException {Token t;
    switch ((jj_ntk==-1)?jj_ntk_f():jj_ntk) {
    case QUOTED_STRING_VAL:{
      t = jj_consume_token(QUOTED_STRING_VAL);
{if ("" != null) return JavaEscape.unescapeJava(t.image.substring(1, t.image.length() - 1));}
      break;
      }
    case LITERAL_VAL:{
      t = jj_consume_token(LITERAL_VAL);
{if ("" != null) return t.image;}
      break;
      }
    default:
      jj_la1[8] = jj_gen;
      jj_consume_token(-1);
      throw new ParseException();
    }
    throw new Error("Missing return statement in function");
}

  final public LinkedList<Element> CloseTag() throws ParseException {LinkedList<Element> elements = new LinkedList<Element>();
    LinkedList<Element> rest = null;
    Token t;
    Token firstToken = getToken(1);
    try {
      jj_consume_token(ENDTAG_START);
      t = jj_consume_token(FUNCTION_NAME);
      jj_consume_token(TAG_END);
elements.add(new Element.EndTag(t.image)); {if ("" != null) return elements;}
    } catch (ParseException e) {
//        System.out.println("Failed End tag. Treating as text");
        elements.addFirst(new Element.TextElement(getTokenText(firstToken, getToken(0))));
    }
    if (jj_2_2(2)) {
      rest = ElementSequence();
    } else {
      ;
    }
if(rest != null) elements.addAll(rest); {if ("" != null) return elements;}
    throw new Error("Missing return statement in function");
}

  private boolean jj_2_1(int xla)
 {
    jj_la = xla; jj_lastpos = jj_scanpos = token;
    try { return (!jj_3_1()); }
    catch(LookaheadSuccess ls) { return true; }
    finally { jj_save(0, xla); }
  }

  private boolean jj_2_2(int xla)
 {
    jj_la = xla; jj_lastpos = jj_scanpos = token;
    try { return (!jj_3_2()); }
    catch(LookaheadSuccess ls) { return true; }
    finally { jj_save(1, xla); }
  }

  private boolean jj_3R_7()
 {
    Token xsp;
    xsp = jj_scanpos;
    if (jj_scan_token(10)) {
    jj_scanpos = xsp;
    if (jj_scan_token(13)) {
    jj_scanpos = xsp;
    if (jj_scan_token(18)) {
    jj_scanpos = xsp;
    if (jj_scan_token(23)) {
    jj_scanpos = xsp;
    if (jj_scan_token(19)) {
    jj_scanpos = xsp;
    if (jj_scan_token(20)) {
    jj_scanpos = xsp;
    if (jj_scan_token(21)) {
    jj_scanpos = xsp;
    if (jj_scan_token(22)) {
    jj_scanpos = xsp;
    if (jj_scan_token(17)) {
    jj_scanpos = xsp;
    if (jj_scan_token(15)) return true;
    }
    }
    }
    }
    }
    }
    }
    }
    }
    return false;
  }

  private boolean jj_3R_6()
 {
    if (jj_scan_token(LESSTHAN)) return true;
    return false;
  }

  private boolean jj_3_2()
 {
    if (jj_3R_3()) return true;
    return false;
  }

  private boolean jj_3R_5()
 {
    if (jj_3R_9()) return true;
    return false;
  }

  private boolean jj_3R_8()
 {
    if (jj_scan_token(TAG_START)) return true;
    if (jj_scan_token(FUNCTION_NAME)) return true;
    return false;
  }

  private boolean jj_3_1()
 {
    if (jj_3R_3()) return true;
    return false;
  }

  private boolean jj_3R_4()
 {
    if (jj_3R_8()) return true;
    return false;
  }

  private boolean jj_3R_3()
 {
    Token xsp;
    xsp = jj_scanpos;
    if (jj_3R_4()) {
    jj_scanpos = xsp;
    if (jj_3R_5()) {
    jj_scanpos = xsp;
    if (jj_3R_6()) {
    jj_scanpos = xsp;
    if (jj_3R_7()) return true;
    }
    }
    }
    return false;
  }

  private boolean jj_3R_9()
 {
    if (jj_scan_token(ENDTAG_START)) return true;
    if (jj_scan_token(FUNCTION_NAME)) return true;
    return false;
  }

  /** Generated Token Manager. */
  public HackvertorParserTokenManager token_source;
  SimpleCharStream jj_input_stream;
  /** Current token. */
  public Token token;
  /** Next token. */
  public Token jj_nt;
  private int jj_ntk;
  private Token jj_scanpos, jj_lastpos;
  private int jj_la;
  private int jj_gen;
  final private int[] jj_la1 = new int[9];
  static private int[] jj_la1_0;
  static {
	   jj_la1_init_0();
	}
	private static void jj_la1_init_0() {
	   jj_la1_0 = new int[] {0xfeaf00,0xfea400,0xfeaf00,0x200000,0x180000,0x4000,0x18000,0x38000,0x180000,};
	}
  final private JJCalls[] jj_2_rtns = new JJCalls[2];
  private boolean jj_rescan = false;
  private int jj_gc = 0;

  /** Constructor with InputStream. */
  public HackvertorParser(java.io.InputStream stream) {
	  this(stream, null);
  }
  /** Constructor with InputStream and supplied encoding */
  public HackvertorParser(java.io.InputStream stream, String encoding) {
	 try { jj_input_stream = new SimpleCharStream(stream, encoding, 1, 1); } catch(java.io.UnsupportedEncodingException e) { throw new RuntimeException(e); }
	 token_source = new HackvertorParserTokenManager(jj_input_stream);
	 token = new Token();
	 jj_ntk = -1;
	 jj_gen = 0;
	 for (int i = 0; i < 9; i++) jj_la1[i] = -1;
	 for (int i = 0; i < jj_2_rtns.length; i++) jj_2_rtns[i] = new JJCalls();
  }

  /** Reinitialise. */
  public void ReInit(java.io.InputStream stream) {
	  ReInit(stream, null);
  }
  /** Reinitialise. */
  public void ReInit(java.io.InputStream stream, String encoding) {
	 try { jj_input_stream.ReInit(stream, encoding, 1, 1); } catch(java.io.UnsupportedEncodingException e) { throw new RuntimeException(e); }
	 token_source.ReInit(jj_input_stream);
	 token = new Token();
	 jj_ntk = -1;
	 jj_gen = 0;
	 for (int i = 0; i < 9; i++) jj_la1[i] = -1;
	 for (int i = 0; i < jj_2_rtns.length; i++) jj_2_rtns[i] = new JJCalls();
  }

  /** Constructor. */
  public HackvertorParser(java.io.Reader stream) {
	 jj_input_stream = new SimpleCharStream(stream, 1, 1);
	 token_source = new HackvertorParserTokenManager(jj_input_stream);
	 token = new Token();
	 jj_ntk = -1;
	 jj_gen = 0;
	 for (int i = 0; i < 9; i++) jj_la1[i] = -1;
	 for (int i = 0; i < jj_2_rtns.length; i++) jj_2_rtns[i] = new JJCalls();
  }

  /** Reinitialise. */
  public void ReInit(java.io.Reader stream) {
	if (jj_input_stream == null) {
	   jj_input_stream = new SimpleCharStream(stream, 1, 1);
	} else {
	   jj_input_stream.ReInit(stream, 1, 1);
	}
	if (token_source == null) {
 token_source = new HackvertorParserTokenManager(jj_input_stream);
	}

	 token_source.ReInit(jj_input_stream);
	 token = new Token();
	 jj_ntk = -1;
	 jj_gen = 0;
	 for (int i = 0; i < 9; i++) jj_la1[i] = -1;
	 for (int i = 0; i < jj_2_rtns.length; i++) jj_2_rtns[i] = new JJCalls();
  }

  /** Constructor with generated Token Manager. */
  public HackvertorParser(HackvertorParserTokenManager tm) {
	 token_source = tm;
	 token = new Token();
	 jj_ntk = -1;
	 jj_gen = 0;
	 for (int i = 0; i < 9; i++) jj_la1[i] = -1;
	 for (int i = 0; i < jj_2_rtns.length; i++) jj_2_rtns[i] = new JJCalls();
  }

  /** Reinitialise. */
  public void ReInit(HackvertorParserTokenManager tm) {
	 token_source = tm;
	 token = new Token();
	 jj_ntk = -1;
	 jj_gen = 0;
	 for (int i = 0; i < 9; i++) jj_la1[i] = -1;
	 for (int i = 0; i < jj_2_rtns.length; i++) jj_2_rtns[i] = new JJCalls();
  }

  private Token jj_consume_token(int kind) throws ParseException {
	 Token oldToken;
	 if ((oldToken = token).next != null) token = token.next;
	 else token = token.next = token_source.getNextToken();
	 jj_ntk = -1;
	 if (token.kind == kind) {
	   jj_gen++;
	   if (++jj_gc > 100) {
		 jj_gc = 0;
		 for (int i = 0; i < jj_2_rtns.length; i++) {
		   JJCalls c = jj_2_rtns[i];
		   while (c != null) {
			 if (c.gen < jj_gen) c.first = null;
			 c = c.next;
		   }
		 }
	   }
	   return token;
	 }
	 token = oldToken;
	 jj_kind = kind;
	 throw generateParseException();
  }

  @SuppressWarnings("serial")
  static private final class LookaheadSuccess extends java.lang.Error { }
  final private LookaheadSuccess jj_ls = new LookaheadSuccess();
  private boolean jj_scan_token(int kind) {
	 if (jj_scanpos == jj_lastpos) {
	   jj_la--;
	   if (jj_scanpos.next == null) {
		 jj_lastpos = jj_scanpos = jj_scanpos.next = token_source.getNextToken();
	   } else {
		 jj_lastpos = jj_scanpos = jj_scanpos.next;
	   }
	 } else {
	   jj_scanpos = jj_scanpos.next;
	 }
	 if (jj_rescan) {
	   int i = 0; Token tok = token;
	   while (tok != null && tok != jj_scanpos) { i++; tok = tok.next; }
	   if (tok != null) jj_add_error_token(kind, i);
	 }
	 if (jj_scanpos.kind != kind) return true;
	 if (jj_la == 0 && jj_scanpos == jj_lastpos) throw jj_ls;
	 return false;
  }


/** Get the next Token. */
  final public Token getNextToken() {
	 if (token.next != null) token = token.next;
	 else token = token.next = token_source.getNextToken();
	 jj_ntk = -1;
	 jj_gen++;
	 return token;
  }

/** Get the specific Token. */
  final public Token getToken(int index) {
	 Token t = token;
	 for (int i = 0; i < index; i++) {
	   if (t.next != null) t = t.next;
	   else t = t.next = token_source.getNextToken();
	 }
	 return t;
  }

  private int jj_ntk_f() {
	 if ((jj_nt=token.next) == null)
	   return (jj_ntk = (token.next=token_source.getNextToken()).kind);
	 else
	   return (jj_ntk = jj_nt.kind);
  }

  private java.util.List<int[]> jj_expentries = new java.util.ArrayList<int[]>();
  private int[] jj_expentry;
  private int jj_kind = -1;
  private int[] jj_lasttokens = new int[100];
  private int jj_endpos;

  private void jj_add_error_token(int kind, int pos) {
	 if (pos >= 100) {
		return;
	 }

	 if (pos == jj_endpos + 1) {
	   jj_lasttokens[jj_endpos++] = kind;
	 } else if (jj_endpos != 0) {
	   jj_expentry = new int[jj_endpos];

	   for (int i = 0; i < jj_endpos; i++) {
		 jj_expentry[i] = jj_lasttokens[i];
	   }

	   for (int[] oldentry : jj_expentries) {
		 if (oldentry.length == jj_expentry.length) {
		   boolean isMatched = true;

		   for (int i = 0; i < jj_expentry.length; i++) {
			 if (oldentry[i] != jj_expentry[i]) {
			   isMatched = false;
			   break;
			 }

		   }
		   if (isMatched) {
			 jj_expentries.add(jj_expentry);
			 break;
		   }
		 }
	   }

	   if (pos != 0) {
		 jj_lasttokens[(jj_endpos = pos) - 1] = kind;
	   }
	 }
  }

  /** Generate ParseException. */
  public ParseException generateParseException() {
	 jj_expentries.clear();
	 boolean[] la1tokens = new boolean[25];
	 if (jj_kind >= 0) {
	   la1tokens[jj_kind] = true;
	   jj_kind = -1;
	 }
	 for (int i = 0; i < 9; i++) {
	   if (jj_la1[i] == jj_gen) {
		 for (int j = 0; j < 32; j++) {
		   if ((jj_la1_0[i] & (1<<j)) != 0) {
			 la1tokens[j] = true;
		   }
		 }
	   }
	 }
	 for (int i = 0; i < 25; i++) {
	   if (la1tokens[i]) {
		 jj_expentry = new int[1];
		 jj_expentry[0] = i;
		 jj_expentries.add(jj_expentry);
	   }
	 }
	 jj_endpos = 0;
	 jj_rescan_token();
	 jj_add_error_token(0, 0);
	 int[][] exptokseq = new int[jj_expentries.size()][];
	 for (int i = 0; i < jj_expentries.size(); i++) {
	   exptokseq[i] = jj_expentries.get(i);
	 }
	 return new ParseException(token, exptokseq, tokenImage);
  }

  private int trace_indent = 0;
  private boolean trace_enabled;

/** Trace enabled. */
  final public boolean trace_enabled() {
	 return trace_enabled;
  }

  /** Enable tracing. */
  final public void enable_tracing() {
  }

  /** Disable tracing. */
  final public void disable_tracing() {
  }

  private void jj_rescan_token() {
	 jj_rescan = true;
	 for (int i = 0; i < 2; i++) {
	   try {
		 JJCalls p = jj_2_rtns[i];

		 do {
		   if (p.gen > jj_gen) {
			 jj_la = p.arg; jj_lastpos = jj_scanpos = p.first;
			 switch (i) {
			   case 0: jj_3_1(); break;
			   case 1: jj_3_2(); break;
			 }
		   }
		   p = p.next;
		 } while (p != null);

		 } catch(LookaheadSuccess ls) { }
	 }
	 jj_rescan = false;
  }

  private void jj_save(int index, int xla) {
	 JJCalls p = jj_2_rtns[index];
	 while (p.gen > jj_gen) {
	   if (p.next == null) { p = p.next = new JJCalls(); break; }
	   p = p.next;
	 }

	 p.gen = jj_gen + xla - jj_la; 
	 p.first = token;
	 p.arg = xla;
  }

  static final class JJCalls {
	 int gen;
	 Token first;
	 int arg;
	 JJCalls next;
  }

}