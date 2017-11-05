package gui;

import java.awt.EventQueue;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

import javax.swing.JFrame;
import javax.swing.JLayeredPane;
import java.awt.BorderLayout;
import java.awt.Color;

import javax.swing.JTabbedPane;
import javax.swing.JPanel;
import javax.swing.JTextField;
import net.miginfocom.swing.MigLayout;
import javax.swing.JLabel;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JCheckBox;
import javax.swing.SwingConstants;
import javax.swing.JFileChooser;
import javax.swing.JTextPane;
import javax.swing.DefaultComboBoxModel;
import javax.swing.JSeparator;
//import com.jgoodies.forms.factories.DefaultComponentFactory;
import javax.swing.border.TitledBorder;

public class Gui {

	private JFrame frmCipherfile;
	private JTextField textField;
	private JTextField textField_1;
	private JTextField textField_2;
	private JFileChooser fileCh1; 
	private JTextField textField_3;
	private JTextField ReceiverID;
	private JTextField idRemoveUserTextField;
	private JTextField idNewUserTextField;
	
	private Browse1_list browse1_listener;

	/**
	 * Launch the application.
	 */
	public static void main(String[] args) {
		EventQueue.invokeLater(new Runnable() {
			public void run() {
				try {
					Gui window = new Gui();
					window.frmCipherfile.setVisible(true);
				} catch (Exception e) {
					e.printStackTrace();
				}
			}
		});
	}

	/**
	 * Create the application.
	 */
	public Gui() {
		initialize();
	}

	/**
	 * Initialize the contents of the frame.
	 */
	private void initialize() {
		frmCipherfile = new JFrame();
		frmCipherfile.setTitle("CipherFile");
		frmCipherfile.setBounds(100, 100, 450, 376);
		frmCipherfile.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		
		JTabbedPane JPane = new JTabbedPane(JTabbedPane.TOP);
		frmCipherfile.getContentPane().add(JPane, BorderLayout.CENTER);
		
		JPanel ChiperPanel = new JPanel();
		JPane.addTab("Cipher", null, ChiperPanel, null);
		ChiperPanel.setLayout(new MigLayout("", "[][grow][grow][][][][][grow]", "[][22px][22px][][][][][][][][]"));
		
		JLabel FileLabel = new JLabel("File");
		FileLabel.setHorizontalAlignment(SwingConstants.LEFT);
		ChiperPanel.add(FileLabel, "cell 0 0,alignx left");
		
		textField_2 = new JTextField();
		ChiperPanel.add(textField_2, "cell 1 0 6 1,growx");
		textField_2.setColumns(10);
		textField_2.setEditable(false);
		textField_2.setBackground(Color.white);
		fileCh1 = new JFileChooser();
		
		JButton FileChooserLabel = new JButton("Browse...");
		ChiperPanel.add(FileChooserLabel, "cell 7 0,alignx center");
		browse1_listener = new Browse1_list();
		FileChooserLabel.addActionListener(browse1_listener);
		
		JLabel IdSenderLabel = new JLabel("ID Sender");
		ChiperPanel.add(IdSenderLabel, "cell 0 1,alignx left");
		
		textField = new JTextField();
		ChiperPanel.add(textField, "cell 1 1 6 1,growx");
		textField.setColumns(10);
		
		JLabel IdReceiverLabel = new JLabel("ID Receiver");
		ChiperPanel.add(IdReceiverLabel, "cell 0 2,alignx left");
		
		textField_1 = new JTextField();
		ChiperPanel.add(textField_1, "cell 1 2 6 1,growx");
		textField_1.setColumns(10);
		
		JLabel CipherLabel = new JLabel("Cipher");
		ChiperPanel.add(CipherLabel, "flowy,cell 0 3,alignx left");
		
		JComboBox comboBox_1 = new JComboBox();
		ChiperPanel.add(comboBox_1, "cell 1 3 6 1,growx");
		
		JLabel ModeLabel = new JLabel("Mode");
		ChiperPanel.add(ModeLabel, "cell 0 4,alignx left");
		
		JComboBox comboBox_2 = new JComboBox();
		ChiperPanel.add(comboBox_2, "cell 1 4 6 1,growx");
		
		JCheckBox SignLabel = new JCheckBox("Sign");
		ChiperPanel.add(SignLabel, "cell 0 6");
		
		JButton CancelLabel = new JButton("Cancel");
		ChiperPanel.add(CancelLabel, "cell 6 10");
		
		JButton OkLabel = new JButton("Ok");
		ChiperPanel.add(OkLabel, "cell 7 10,alignx center");
		
		JPanel Decipher = new JPanel();
		JPane.addTab("Decipher", null, Decipher, null);
		Decipher.setLayout(new MigLayout("", "[grow][grow][]", "[][][grow][]"));
		
		JLabel ReceiverId = new JLabel("Receiver ID");
		Decipher.add(ReceiverId, "cell 0 0,alignx left,aligny top");
		
		ReceiverID = new JTextField();
		Decipher.add(ReceiverID, "cell 1 0 2 1,growx");
		ReceiverID.setColumns(10);
		
		JLabel FileLabelDecipher = new JLabel("File");
		Decipher.add(FileLabelDecipher, "cell 0 1,alignx left");
		
		textField_3 = new JTextField();
		Decipher.add(textField_3, "cell 1 1,growx");
		textField_3.setColumns(10);
		
		JButton loadButtonDecipher = new JButton("load");
		Decipher.add(loadButtonDecipher, "cell 2 1,alignx center");
		
		JTextPane textPane = new JTextPane();
		Decipher.add(textPane, "cell 0 2 3 1,grow");
		
		JButton cancelButtonDecipher = new JButton("Cancel");
		Decipher.add(cancelButtonDecipher, "flowx,cell 1 3,alignx right,aligny center");
		
		JButton okButtonDecipher = new JButton("Ok");
		Decipher.add(okButtonDecipher, "cell 2 3,alignx center,aligny center");
		
		JPanel UsersPanel = new JPanel();
		JPane.addTab("Users", null, UsersPanel, null);
		UsersPanel.setLayout(new MigLayout("", "[grow][grow][][][]", "[grow][][][][][][][][][][][][grow][]"));
		
		JPanel addUserPanel = new JPanel();
		addUserPanel.setBorder(new TitledBorder(null, "Add User", TitledBorder.LEADING, TitledBorder.TOP, null, null));
		UsersPanel.add(addUserPanel, "cell 0 0 5 12,grow");
		addUserPanel.setLayout(new MigLayout("", "[12px][][grow][116px,grow][73px][55px][45px][5px][58px][5px][46px][5px][74px][55px][53px][120px]", "[][][][][][]"));
		
		JLabel idNewUserLabel = new JLabel("ID");
		addUserPanel.add(idNewUserLabel, "cell 1 0");
		
		idNewUserTextField = new JTextField();
		addUserPanel.add(idNewUserTextField, "cell 3 0 13 1,growx");
		idNewUserTextField.setColumns(10);
		
		JLabel rsaKeySizeLabel = new JLabel("RSA key size");
		addUserPanel.add(rsaKeySizeLabel, "cell 1 1");
		
		JComboBox rsaKeySizeComboBox = new JComboBox();
		rsaKeySizeComboBox.setModel(new DefaultComboBoxModel(new String[] {"1024", "2048"}));
		addUserPanel.add(rsaKeySizeComboBox, "cell 3 1 13 1,growx");
		
		JLabel paddingLabel = new JLabel("Padding");
		addUserPanel.add(paddingLabel, "cell 1 2");
		
		JComboBox paddingComboBox = new JComboBox();
		paddingComboBox.setModel(new DefaultComboBoxModel(new String[] {"PKCS1Padding", "OAEPPadding"}));
		addUserPanel.add(paddingComboBox, "cell 3 2 13 1,growx");
		
		JLabel signKeySizeLabel = new JLabel("Sign key size");
		addUserPanel.add(signKeySizeLabel, "cell 1 3");
		
		JComboBox signKeySizeComboBox = new JComboBox();
		signKeySizeComboBox.setModel(new DefaultComboBoxModel(new String[] {"1024", "2048"}));
		addUserPanel.add(signKeySizeComboBox, "cell 3 3 13 1,growx");
		
		JLabel signTypeLabel = new JLabel("Sign type");
		addUserPanel.add(signTypeLabel, "cell 1 4");
		
		JComboBox signTypeComboBox = new JComboBox();
		signTypeComboBox.setModel(new DefaultComboBoxModel(new String[] {"SHA1withDSA", "SHA224withDSA", "SHA256withDSA"}));
		addUserPanel.add(signTypeComboBox, "cell 3 4 13 1,growx");
		
		JButton cancelNewUserButton = new JButton("Cancel");
		addUserPanel.add(cancelNewUserButton, "cell 12 5,alignx right,aligny top");
		
		JButton addNewUserButton = new JButton("Add");
		addUserPanel.add(addNewUserButton, "cell 15 5,alignx left,aligny top");
		
		JPanel removeUserPanel = new JPanel();
		removeUserPanel.setBorder(new TitledBorder(null, "Remove User", TitledBorder.LEADING, TitledBorder.TOP, null, null));
		UsersPanel.add(removeUserPanel, "cell 0 12 5 2,grow");
		removeUserPanel.setLayout(new MigLayout("", "[12px][116px,grow][71px][79px][]", "[25px][]"));
		
		JLabel idUserRemoveLabel = new JLabel("ID");
		removeUserPanel.add(idUserRemoveLabel, "cell 0 0,alignx trailing,aligny center");
		
		idRemoveUserTextField = new JTextField();
		removeUserPanel.add(idRemoveUserTextField, "cell 1 0 4 1,growx");
		idRemoveUserTextField.setColumns(10);
		
		JButton cancelRemoveUserButton = new JButton("Cancel");
		removeUserPanel.add(cancelRemoveUserButton, "cell 3 1,alignx left,aligny top");
		
		JButton removeUserButton = new JButton("Remove");
		removeUserPanel.add(removeUserButton, "cell 4 1,alignx left,aligny top");
	}
	
	private class Browse1_list implements ActionListener {
        public void actionPerformed(ActionEvent evt) {
        	fileCh1.showOpenDialog(null);
        	textField_2.setText(fileCh1.getSelectedFile().getPath());
        }
}

}
