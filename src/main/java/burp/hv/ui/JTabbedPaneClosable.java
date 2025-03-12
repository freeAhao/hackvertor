package burp.hv.ui;

import javax.swing.*;
import java.awt.*;
import java.awt.event.*;

public class JTabbedPaneClosable extends JTabbedPane {
    public boolean clickedDelete = false;

    public JTabbedPaneClosable() {
        super();
    }

    @Override
    public void addTab(String title, Icon icon, Component component, String tip) {
        super.addTab(title, icon, component, tip);
    }

    @Override
    public void addTab(String title, Icon icon, Component component) {
        addTab(title, icon, component, null);
    }

    @Override
    public void addTab(String title, Component component) {
        addTab(title, null, component);
    }

    @Override
    public void insertTab(String title, Icon icon, Component component, String tip, int index) {
        super.insertTab(title, icon, component, tip, index);
        if (!title.equals("...")) {
            setTabComponentAt(index, new CloseButtonTab(component, title, icon));
        }
    }

    public void addTabNoExit(String title, Icon icon, Component component, String tip) {
        super.addTab(title, icon, component, tip);
    }

    public void addTabNoExit(String title, Icon icon, Component component) {
        addTabNoExit(title, icon, component, null);
    }

    public void addTabNoExit(String title, Component component) {
        addTabNoExit(title, null, component);
    }

    public class CloseButtonTab extends JPanel {
        private Component tab;

        public CloseButtonTab(final Component tab, String title, Icon icon) {
            this.tab = tab;
            setOpaque(false);
            setLayout(new GridBagLayout());
            GridBagConstraints c = new GridBagConstraints();
            c.fill = GridBagConstraints.HORIZONTAL;
            c.gridx = 0;
            c.gridy = 0;
            c.weightx = 0.5;
            c.gridwidth = 1;
            c.ipadx = 8;
            final JTextField textField = new JTextField(title);
            textField.setOpaque(false);
            textField.setBackground(new Color(0, 0, 0, 0));
            textField.setBorder(null);
            textField.setEditable(false);
            textField.addMouseListener(new MouseAdapter() {
                @Override
                public void mouseClicked(MouseEvent e) {
                    if (e.getClickCount() == 2) {
                        textField.setEditable(true);
                    }
                    if (e.getClickCount() == 1) {
                        JTabbedPaneClosable tabbedPane = (JTabbedPaneClosable) textField.getParent().getParent().getParent();
                        tabbedPane.setSelectedIndex(tabbedPane.indexOfComponent(tab));
                    }
                }
            });
            textField.addFocusListener(new FocusAdapter() {
                public void focusLost(FocusEvent e) {
                    textField.setEditable(false);
                }
            });
            add(textField, c);
            JLabel close = new JLabel("x");
//            close.setFont(new Font("Courier", Font.PLAIN, 10));
            close.setFont(new Font("Source Han Sans CN", Font.PLAIN, 10));
            close.setPreferredSize(new Dimension(10, 10));
            close.setBorder(null);
            close.addMouseListener(new CloseListener(tab));
            c.gridx = 1;
            add(close, c);
        }
    }

    public class CloseListener implements MouseListener {
        private Component tab;

        public CloseListener(Component tab) {
            this.tab = tab;
        }

        @Override
        public void mouseClicked(MouseEvent e) {
            if (e.getSource() instanceof JLabel) {
                JLabel clickedButton = (JLabel) e.getSource();
                JTabbedPaneClosable tabbedPane = (JTabbedPaneClosable) clickedButton.getParent().getParent().getParent();
                clickedDelete = true;
                tabbedPane.remove(tab);
            }
        }

        @Override
        public void mousePressed(MouseEvent e) {
        }

        @Override
        public void mouseReleased(MouseEvent e) {
        }

        @Override
        public void mouseEntered(MouseEvent e) {
            if (e.getSource() instanceof JButton) {
                JButton clickedButton = (JButton) e.getSource();
            }
        }

        @Override
        public void mouseExited(MouseEvent e) {
            if (e.getSource() instanceof JButton) {
                JButton clickedButton = (JButton) e.getSource();
            }
        }
    }
}