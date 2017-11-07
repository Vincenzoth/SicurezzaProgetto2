package gui;

import java.awt.EventQueue;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;

import javax.swing.JFrame;
import javax.swing.JOptionPane;

import java.awt.BorderLayout;
import java.awt.Color;

import javax.swing.JTabbedPane;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.JTextField;
import net.miginfocom.swing.MigLayout;
import progetto.Incapsula;
import progetto.KeyManager;
import progetto.MyException;

import javax.swing.JLabel;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JCheckBox;
import javax.swing.SwingConstants;
import javax.swing.UIManager;
import javax.swing.JFileChooser;
import javax.swing.JTextPane;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.swing.DefaultComboBoxModel;
import javax.swing.border.TitledBorder;

public class Gui {

	private JFrame frmCipherfile;
	private JComboBox<String> type_cipher_comboBox;
	private JComboBox<String> paddingMode_cipher_comboBox;
	private JComboBox<String> idSenderComboBox;
	private JComboBox<String> idReceiverComboBox;	

	private JCheckBox signLabel_cipher;
	private JTextField file_cipher_textField;
	private JFileChooser fileCh1; 
	private JTextField file_decipher_textField;
	private JFileChooser fileCh2; 
	private JTextPane result_decipher_textPane;
	private JTextField idNewUserTextField;
	private JComboBox<String> rsaKeySizeComboBox;
	private JComboBox<String> paddingComboBox;
	private JComboBox<String> signKeySizeComboBox;
	private JComboBox<String> signTypeComboBox;
	private JComboBox<String> idReceiverDecipherComboBox;
	private JComboBox<String> removeUserComboBox;

	private Browse1_list browse1_listener;
	private OkCipher_list okCipher_listener;
	private Browse2_list browse2_listener;
	private OkDecipher_list okDecipher_listener;
	private NewUSer_list but_addUser_listener;
	private RemoveUser_list but_RemoveUser_listener;

	private KeyManager km;
	private Incapsula inc;

	/**
	 * Launch the application.
	 */
	public static void main(String[] args) {
		EventQueue.invokeLater(new Runnable() {
			public void run() {
				try {
					// set system look&Feel
					UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());

					JPasswordField pf = new JPasswordField();
					int getPass = JOptionPane.showConfirmDialog(null, pf, "Enter Password", JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE);

					if (getPass == JOptionPane.OK_OPTION) {						
						String password = new String(pf.getPassword());
						//password = "qwerty";						
						Gui window = new Gui(password);						
						window.frmCipherfile.setVisible(true);
					}
				} catch (Exception e) {
					JOptionPane.showMessageDialog(null,"Password non valida", "Error", JOptionPane.ERROR_MESSAGE);
				}
			}
		});
	}

	/**
	 * Create the application.
	 * @throws IOException 
	 * @throws InvalidKeySpecException 
	 * @throws ClassNotFoundException 
	 * @throws NoSuchPaddingException 
	 * @throws NoSuchAlgorithmException 
	 * @throws InvalidKeyException 
	 */
	public Gui(String password) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, ClassNotFoundException, InvalidKeySpecException, IOException {

		km = new KeyManager(password);
		inc = new Incapsula(km);				

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
		ChiperPanel.setLayout(new MigLayout("", "[][grow][grow][][][][][]", "[][22px][22px][][][][][grow]"));

		// ------- tab cipher -----------------------------------------------------------------------------------------------------
		// ------------------------------------------------------------------------------------------------------------------------
		JLabel FileLabel = new JLabel("File");
		FileLabel.setHorizontalAlignment(SwingConstants.LEFT);
		ChiperPanel.add(FileLabel, "cell 0 0,alignx left");

		file_cipher_textField = new JTextField();
		ChiperPanel.add(file_cipher_textField, "cell 1 0 6 1,growx");
		file_cipher_textField.setColumns(10);
		file_cipher_textField.setEditable(false);
		file_cipher_textField.setBackground(Color.white);
		fileCh1 = new JFileChooser();

		JButton FileChooserLabel = new JButton("Browse...");
		ChiperPanel.add(FileChooserLabel, "cell 7 0,alignx center");
		browse1_listener = new Browse1_list();
		FileChooserLabel.addActionListener(browse1_listener);

		JLabel IdSenderLabel = new JLabel("ID Sender");
		ChiperPanel.add(IdSenderLabel, "cell 0 1,alignx left");
		idSenderComboBox = new JComboBox<String>();						
		idSenderComboBox.setModel(new DefaultComboBoxModel<String>(km.getAllUsers()));
		ChiperPanel.add(idSenderComboBox, "cell 1 1 6 1,growx");		

		JLabel IdReceiverLabel = new JLabel("ID Receiver");
		ChiperPanel.add(IdReceiverLabel, "cell 0 2,alignx trailing");
		idReceiverComboBox = new JComboBox<String>();
		idReceiverComboBox.setModel(new DefaultComboBoxModel<String>(km.getAllUsers()));
		ChiperPanel.add(idReceiverComboBox, "cell 1 2 6 1,growx");

		JLabel CipherLabel = new JLabel("Cipher");
		ChiperPanel.add(CipherLabel, "flowy,cell 0 3,alignx left");
		type_cipher_comboBox = new JComboBox<String>();
		type_cipher_comboBox.setModel(new DefaultComboBoxModel<String>(new String[] {"AES", "DES", "DESede"}));
		ChiperPanel.add(type_cipher_comboBox, "cell 1 3 6 1,growx");


		JLabel ModeLabel = new JLabel("Mode");
		ChiperPanel.add(ModeLabel, "cell 0 4,alignx left");
		paddingMode_cipher_comboBox = new JComboBox<String>();
		paddingMode_cipher_comboBox.setModel(new DefaultComboBoxModel<String>(new String[] {"ECB", "CBC", "CFB"}));
		ChiperPanel.add(paddingMode_cipher_comboBox, "cell 1 4 6 1,growx");

		signLabel_cipher = new JCheckBox("Sign");
		ChiperPanel.add(signLabel_cipher, "cell 0 6");

		JButton CancelLabel = new JButton("Cancel");
		ChiperPanel.add(CancelLabel, "cell 6 7,aligny bottom");

		JButton OkLabel = new JButton("Ok");
		ChiperPanel.add(OkLabel, "cell 7 7,alignx center,aligny bottom");
		okCipher_listener = new OkCipher_list();
		OkLabel.addActionListener(okCipher_listener);

		// ------- tab decipher ---------------------------------------------------------------------------------------------------
		// ------------------------------------------------------------------------------------------------------------------------

		JPanel Decipher = new JPanel();
		JPane.addTab("Decipher", null, Decipher, null);
		Decipher.setLayout(new MigLayout("", "[][grow][]", "[][][grow][]"));

		JLabel ReceiverId = new JLabel("Receiver ID");
		Decipher.add(ReceiverId, "cell 0 0,alignx left,aligny top");

		idReceiverDecipherComboBox = new JComboBox<String>();
		idReceiverDecipherComboBox.setModel(new DefaultComboBoxModel<String>(km.getAllUsers()));
		Decipher.add(idReceiverDecipherComboBox, "cell 1 0 2 1,growx");

		JLabel FileLabelDecipher = new JLabel("File");
		Decipher.add(FileLabelDecipher, "cell 0 1,alignx left");
		file_decipher_textField = new JTextField();
		Decipher.add(file_decipher_textField, "cell 1 1,growx");
		//file_decipher_textField.setColumns(10);
		file_decipher_textField.setEditable(false);
		file_decipher_textField.setBackground(Color.white);
		fileCh2 = new JFileChooser();

		JButton loadButtonDecipher = new JButton("Browse...");
		Decipher.add(loadButtonDecipher, "cell 2 1,alignx center");
		browse2_listener = new Browse2_list();
		loadButtonDecipher.addActionListener(browse2_listener);


		result_decipher_textPane = new JTextPane();
		result_decipher_textPane.setEditable(false);
		Decipher.add(result_decipher_textPane, "cell 0 2 3 1,grow");

		JButton cancelButtonDecipher = new JButton("Cancel");
		Decipher.add(cancelButtonDecipher, "flowx,cell 1 3,alignx right,aligny center");

		JButton okButtonDecipher = new JButton("Ok");
		Decipher.add(okButtonDecipher, "cell 2 3,alignx center,aligny center");
		okDecipher_listener = new OkDecipher_list();
		okButtonDecipher.addActionListener(okDecipher_listener);

		// ------- tab User -------------------------------------------------------------------------------------------------------
		// ------------------------------------------------------------------------------------------------------------------------

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

		rsaKeySizeComboBox = new JComboBox<String>();
		rsaKeySizeComboBox.setModel(new DefaultComboBoxModel<String>(new String[] {"1024", "2048"}));
		addUserPanel.add(rsaKeySizeComboBox, "cell 3 1 13 1,growx");

		JLabel paddingLabel = new JLabel("Padding");
		addUserPanel.add(paddingLabel, "cell 1 2");

		paddingComboBox = new JComboBox<String>();
		paddingComboBox.setModel(new DefaultComboBoxModel<String>(new String[] {"PKCS1Padding", "OAEPPadding"}));
		addUserPanel.add(paddingComboBox, "cell 3 2 13 1,growx");

		JLabel signKeySizeLabel = new JLabel("Sign key size");
		addUserPanel.add(signKeySizeLabel, "cell 1 3");

		signKeySizeComboBox = new JComboBox<String>();
		signKeySizeComboBox.setModel(new DefaultComboBoxModel<String>(new String[] {"1024", "2048"}));
		addUserPanel.add(signKeySizeComboBox, "cell 3 3 13 1,growx");

		JLabel signTypeLabel = new JLabel("Sign type");
		addUserPanel.add(signTypeLabel, "cell 1 4");

		signTypeComboBox = new JComboBox<String>();
		signTypeComboBox.setModel(new DefaultComboBoxModel<String>(new String[] {"SHA1withDSA", "SHA224withDSA", "SHA256withDSA"}));
		addUserPanel.add(signTypeComboBox, "cell 3 4 13 1,growx");

		JButton cancelNewUserButton = new JButton("Cancel");
		addUserPanel.add(cancelNewUserButton, "cell 12 5,alignx right,aligny top");

		JButton addNewUserButton = new JButton("Add");
		addUserPanel.add(addNewUserButton, "cell 15 5,alignx left,aligny top");
		but_addUser_listener = new NewUSer_list();
		addNewUserButton.addActionListener(but_addUser_listener);

		JPanel removeUserPanel = new JPanel();
		removeUserPanel.setBorder(new TitledBorder(null, "Remove User", TitledBorder.LEADING, TitledBorder.TOP, null, null));
		UsersPanel.add(removeUserPanel, "cell 0 12 5 2,grow");
		removeUserPanel.setLayout(new MigLayout("", "[12px][116px,grow][71px][79px][]", "[25px][]"));

		JLabel idUserRemoveLabel = new JLabel("ID");
		removeUserPanel.add(idUserRemoveLabel, "cell 0 0,alignx trailing,aligny center");

		removeUserComboBox = new JComboBox<String>();
		removeUserComboBox.setModel(new DefaultComboBoxModel<String>(km.getAllUsers()));
		removeUserPanel.add(removeUserComboBox, "cell 1 0 4 1,growx");

		JButton cancelRemoveUserButton = new JButton("Cancel");
		removeUserPanel.add(cancelRemoveUserButton, "cell 3 1,alignx left,aligny top");

		JButton removeUserButton = new JButton("Remove");
		removeUserPanel.add(removeUserButton, "cell 4 1,alignx left,aligny top");
		but_RemoveUser_listener = new RemoveUser_list();
		removeUserButton.addActionListener(but_RemoveUser_listener);
	}

	private class Browse1_list implements ActionListener {
		public void actionPerformed(ActionEvent evt) {
			fileCh1.showOpenDialog(null);
			file_cipher_textField.setText(fileCh1.getSelectedFile().getPath());
		}
	}

	private class OkCipher_list implements ActionListener {
		public void actionPerformed(ActionEvent evt) {
			try {	
				String filePath = file_cipher_textField.getText();
				String IDSender = idSenderComboBox.getSelectedItem().toString();
				String IDreceiver = idReceiverComboBox.getSelectedItem().toString();
				String cipherType = type_cipher_comboBox.getSelectedItem().toString();
				String mode = paddingMode_cipher_comboBox.getSelectedItem().toString();
				boolean sig = signLabel_cipher.isSelected();


				inc.initCipher(cipherType, mode, "PKCS5Padding");
				inc.writeCipherFile(filePath, IDSender, IDreceiver, sig);


				JOptionPane.showMessageDialog(null, "FIle cifrato con successo!");
			} catch (InvalidKeyException | IOException | NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException | BadPaddingException | SignatureException e) {
				JOptionPane.showMessageDialog(null, e.getStackTrace(), "Error", JOptionPane.ERROR_MESSAGE);
			}
		}
	}

	// ---- tab Decipher --------------------------------------------------------------------------------------
	// --------------------------------------------------------------------------------------------------------

	private class Browse2_list implements ActionListener {
		public void actionPerformed(ActionEvent evt) {
			fileCh2.showOpenDialog(null);
			file_decipher_textField.setText(fileCh2.getSelectedFile().getPath());
		}
	}

	private class OkDecipher_list implements ActionListener {
		public void actionPerformed(ActionEvent evt) {
			try {	

				String filePath = file_decipher_textField.getText();
				String IDreceiver = idReceiverDecipherComboBox.getSelectedItem().toString();

				int isVer = inc.writeDecipherFile(filePath, IDreceiver);


				if(isVer == 1)
					result_decipher_textPane.setText("La firma è valida");
				else if (isVer == -1)
					result_decipher_textPane.setText("La firma NON è valida");
				else
					result_decipher_textPane.setText("Il file non è firmato");


				JOptionPane.showMessageDialog(null, "File decifrato con successo!");
			} catch (InvalidKeyException | IOException | NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException | BadPaddingException | SignatureException | InvalidKeySpecException | InvalidAlgorithmParameterException | MyException e) {
				JOptionPane.showMessageDialog(null, e.getStackTrace(), "Error", JOptionPane.ERROR_MESSAGE);
			}
		}
	}


	// ---- tab User --- --------------------------------------------------------------------------------------
	// --------------------------------------------------------------------------------------------------------

	private class NewUSer_list implements ActionListener {
		public void actionPerformed(ActionEvent evt) {
			try {				
				String ID = idNewUserTextField.getText();
				int keyLenCod = Integer.parseInt(rsaKeySizeComboBox.getSelectedItem().toString());
				String paddingMode = paddingComboBox.getSelectedItem().toString();
				int keyLenVer = Integer.parseInt(signKeySizeComboBox.getSelectedItem().toString());
				String sigType = signTypeComboBox.getSelectedItem().toString();
				
			
				if(km.newUser(ID, keyLenCod, paddingMode, keyLenVer, sigType) )
					JOptionPane.showMessageDialog(null, "Nuovo utente inserito");
				else
					JOptionPane.showMessageDialog(null, "Impossibile aggiungere l'utente\n E' gia presente un utente con l'ID scelto", "Error", JOptionPane.ERROR_MESSAGE);
					

				// aggiorna comboBox
				idSenderComboBox.setModel(new DefaultComboBoxModel<String>(km.getAllUsers()));
				idReceiverComboBox.setModel(new DefaultComboBoxModel<String>(km.getAllUsers()));
				idReceiverDecipherComboBox.setModel(new DefaultComboBoxModel<String>(km.getAllUsers()));
				removeUserComboBox.setModel(new DefaultComboBoxModel<String>(km.getAllUsers()));

			} catch (InvalidKeyException | NoSuchAlgorithmException | IOException | MyException e) {
				JOptionPane.showMessageDialog(null, e.getStackTrace(), "Error", JOptionPane.ERROR_MESSAGE);
			}
		}
	}

	private class RemoveUser_list implements ActionListener {
		public void actionPerformed(ActionEvent evt) {
			try {				
				String ID = removeUserComboBox.getSelectedItem().toString();

				if(km.removeUser(ID))
					JOptionPane.showMessageDialog(null, "Utente rimosso");
				else
					JOptionPane.showMessageDialog(null, "Impossibile rimuovere l'utente", "Error", JOptionPane.ERROR_MESSAGE);
				
				// aggiorna comboBox
				idSenderComboBox.setModel(new DefaultComboBoxModel<String>(km.getAllUsers()));
				idReceiverComboBox.setModel(new DefaultComboBoxModel<String>(km.getAllUsers()));
				idReceiverDecipherComboBox.setModel(new DefaultComboBoxModel<String>(km.getAllUsers()));
				removeUserComboBox.setModel(new DefaultComboBoxModel<String>(km.getAllUsers()));
			} catch (InvalidKeyException | IOException e) {
				JOptionPane.showMessageDialog(null, e.getStackTrace(), "Error", JOptionPane.ERROR_MESSAGE);
			}
		}
	}

}
