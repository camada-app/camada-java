package dev.camada.snapshot;

/**
 * A CharSequence that stops a runaway regex: java.util.regex has no match timeout, but it reads its
 * input through charAt, so every 256th read checks the clock and throws {@link
 * RegexBudgetExceeded}.
 */
final class Deadline implements CharSequence {
  /** Thrown past the deadline. No stack trace: it is control flow, mapped by Parser.find. */
  static final class RegexBudgetExceeded extends RuntimeException {
    private static final long serialVersionUID = 1L;

    RegexBudgetExceeded() {
      super("regex budget exceeded", null, false, false);
    }
  }

  private final CharSequence s;
  private final long deadline; // System.nanoTime()
  private int reads;

  Deadline(CharSequence s, long deadline) {
    this.s = s;
    this.deadline = deadline;
  }

  @Override
  public char charAt(int i) {
    if ((++reads & 255) == 0 && System.nanoTime() - deadline > 0) {
      throw new RegexBudgetExceeded();
    }
    return s.charAt(i);
  }

  @Override
  public int length() {
    return s.length();
  }

  @Override
  public CharSequence subSequence(int start, int end) {
    return new Deadline(s.subSequence(start, end), deadline);
  }

  @Override
  public String toString() {
    return s.toString();
  }
}
