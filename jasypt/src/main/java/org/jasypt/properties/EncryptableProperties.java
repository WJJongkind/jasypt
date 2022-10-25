/*
 * =============================================================================
 * 
 *   Copyright (c) 2007-2010, The JASYPT team (http://www.jasypt.org)
 * 
 *   Licensed under the Apache License, Version 2.0 (the "License");
 *   you may not use this file except in compliance with the License.
 *   You may obtain a copy of the License at
 * 
 *       http://www.apache.org/licenses/LICENSE-2.0
 * 
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS,
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *   See the License for the specific language governing permissions and
 *   limitations under the License.
 * 
 * =============================================================================
 */
package org.jasypt.properties;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.util.Collection;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Properties;
import java.util.Set;

import org.jasypt.commons.CommonUtils;
import org.jasypt.encryption.StringEncryptor;
import org.jasypt.exceptions.EncryptionOperationNotPossibleException;
import org.jasypt.util.text.TextEncryptor;



/**
 * <p>
 * Subclass of <tt>java.util.Properties</tt> which can make use of a 
 * {@link org.jasypt.encryption.StringEncryptor} or 
 * {@link org.jasypt.util.text.TextEncryptor} object to decrypt property values
 * if they are encrypted in the <tt>.properties</tt> file.
 * </p>
 * <p>
 * A value is considered "encrypted" when it appears surrounded by 
 * <tt>ENC(...)</tt>, like:
 * </p>
 * <p>
 *   <center>
 *     <tt>my.value=ENC(!"DGAS24FaIO$)</tt>
 *   </center>
 * </p>
 * <p>
 * Decryption is performed on-the-fly when the {@link #getProperty(String)},
 * {@link #getProperty(String, String)} or {@link #get(Object)} methods are called.
 * Load and store operations are not affected by decryption in any manner.
 * </p>
 * <p>
 * Encrypted and unencrypted objects can be combined in the same 
 * properties file.
 * </p>
 * <p>
 * Please note that, although objects of this class are Serializable, they
 * cannot be serialized and then de-serialized in different classloaders or
 * virtual machines. This is so because encryptors are not serializable themselves
 * (they cannot, as they contain sensitive information) and so they remain
 * in memory, and live for as long as the classloader lives.
 * </p>
 * 
 * @since 1.4
 * 
 * @author Daniel Fern&aacute;ndez
 * 
 */
public final class EncryptableProperties extends Properties {

    private static final long serialVersionUID = 6479795856725500639L;

    /*
     * Used as an identifier for the encryptor registry
     */
    private final Integer ident = new Integer(CommonUtils.nextRandomInt());

    /*
     * The string encryptor to be used for properties. Either this or the
     * 'textEncryptor' property have to be non-null. 
     */
    private transient StringEncryptor stringEncryptor = null;
    
    /*
     * The text encryptor to be used for properties. Either this or the
     * 'stringEncryptor' property have to be non-null. 
     */
    private transient TextEncryptor textEncryptor = null;
    
    
    /**
     * <p>
     * Creates an <tt>EncryptableProperties</tt> instance which will use
     * the passed {@link StringEncryptor} object to decrypt encrypted values.
     * </p>
     * 
     * @param stringEncryptor the {@link StringEncryptor} to be used do decrypt
     *                        values. It can not be null.
     */
    public EncryptableProperties(final StringEncryptor stringEncryptor) {
        this(null, stringEncryptor);
    }
    

    /**
     * <p>
     * Creates an <tt>EncryptableProperties</tt> instance which will use
     * the passed {@link TextEncryptor} object to decrypt encrypted values.
     * </p>
     * 
     * @param textEncryptor the {@link TextEncryptor} to be used do decrypt
     *                      values. It can not be null.
     */
    public EncryptableProperties(final TextEncryptor textEncryptor) {
        this(null, textEncryptor);
    }
    

    /**
     * <p>
     * Creates an <tt>EncryptableProperties</tt> instance which will use
     * the passed {@link StringEncryptor} object to decrypt encrypted values,
     * and the passed defaults as default values (may contain encrypted values).
     * </p>
     * 
     * @param defaults default values for properties (may be encrypted).
     * @param stringEncryptor the {@link StringEncryptor} to be used do decrypt
     *                        values. It can not be null.
     */
    public EncryptableProperties(final Properties defaults, final StringEncryptor stringEncryptor) {
        super(defaults);
        CommonUtils.validateNotNull(stringEncryptor, "Encryptor cannot be null");
        this.stringEncryptor = stringEncryptor;
        this.textEncryptor = null;
    }


    /**
     * <p>
     * Creates an <tt>EncryptableProperties</tt> instance which will use
     * the passed {@link TextEncryptor} object to decrypt encrypted values,
     * and the passed defaults as default values (may contain encrypted values).
     * </p>
     * 
     * @param defaults default values for properties (may be encrypted).
     * @param textEncryptor the {@link TextEncryptor} to be used do decrypt
     *                      values. It can not be null.
     */
    public EncryptableProperties(final Properties defaults, final TextEncryptor textEncryptor) {
        super(defaults);
        CommonUtils.validateNotNull(textEncryptor, "Encryptor cannot be null");
        this.stringEncryptor = null;
        this.textEncryptor = textEncryptor;
    }


    /**
     * <p>
     * Obtains the property value for the specified key (see 
     * {@link Properties#getProperty(String)}), decrypting it if needed.
     * </p>
     * 
     * @param key the property key
     * @return the (decrypted) value
     */
    @Override
    public String getProperty(final String key) {
        return decode(super.getProperty(key));
    }
    

    /**
     * <p>
     * Obtains the property value for the specified key (see 
     * {@link Properties#getProperty(String)}), decrypting it if needed.
     * </p>
     * <p>
     * If no value is found for the specified key, the default value will
     * be returned (decrypted if needed).
     * </p>
     * 
     * @param key the property key
     * @param defaultValue the default value to return
     * @return the (decrypted) value
     */
    @Override
    public String getProperty(final String key, final String defaultValue) {
        return decode(super.getProperty(key, defaultValue));
    }


    /**
     * <p>
     * Obtains the property value for the specified key (see 
     * {@link Hashtable#get(Object)}), decrypting it if needed.
     * </p>
     * 
     * @param key the property key
     * @return the (decrypted) value
     * @since 1.9.0
     */
    @Override
    public synchronized Object get(final Object key) {
        final Object value = super.get(key);
        final String valueStr = (value instanceof String) ? (String)value : null;
        return decode(valueStr);
    }

    @Override
    public Enumeration<Object> elements() {
        return new DecodedElementEnumeration(super.elements());
    }

    @Override
    public Set<Map.Entry<Object, Object>> entrySet() {
        /*
         * Because we don't know how often an entry in the set is read, it may be more efficient to decode
         * all elements upfront. This is at risk of decoding entries that end up never being used, but with the
         * benefit that entries are never decoded twice.
         *
         * Implementations were considered that lazily
         */
        final Set<Map.Entry<Object, Object>> encodedEntrySet = super.entrySet();
        final LazilyDecodedReadOnlyEntrySet decodedEntrySet = new LazilyDecodedReadOnlyEntrySet(encodedEntrySet.size());
        for (final Entry<Object, Object> entry : super.entrySet()) {
            decodedEntrySet.addEncoded(entry.getKey(), entry.getValue());
        }

        // Similar behavior to Properties; ensure a synchronized set is returned.
        return Collections.synchronizedSet(decodedEntrySet);
    }
    
    /*
     *  Returns the identifier, just to be used by the registry
     */
    Integer getIdent() {
        return this.ident;
    }

    /*
     * Internal method for decoding (decrypting) a value if needed.
     */
    private synchronized String decode(final String encodedValue) {
        
        if (!PropertyValueEncryptionUtils.isEncryptedValue(encodedValue)) {
            return encodedValue;
        }
        if (this.stringEncryptor != null) {
            return PropertyValueEncryptionUtils.decrypt(encodedValue, this.stringEncryptor);
            
        }
        if (this.textEncryptor != null) {
            return PropertyValueEncryptionUtils.decrypt(encodedValue, this.textEncryptor);
        }
        
        /*
         * If neither a StringEncryptor nor a TextEncryptor can be retrieved
         * from the registry, this means that this EncryptableProperties
         * object has been serialized and then deserialized in a different
         * classloader and virtual machine, which is an unsupported behaviour. 
         */
        throw new EncryptionOperationNotPossibleException(
                "Neither a string encryptor nor a text encryptor exist " +
                "for this instance of EncryptableProperties. This is usually " +
                "caused by the instance having been serialized and then " +
                "de-serialized in a different classloader or virtual machine, " +
                "which is an unsupported behaviour (as encryptors cannot be " +
                "serialized themselves)");
        
    }

    

    private void readObject(final ObjectInputStream in) throws IOException, ClassNotFoundException {
        
        in.defaultReadObject();
        
        final EncryptablePropertiesEncryptorRegistry registry =
                EncryptablePropertiesEncryptorRegistry.getInstance();
        
        final StringEncryptor registeredStringEncryptor = registry.getStringEncryptor(this);
        if (registeredStringEncryptor != null) {
            this.stringEncryptor = registeredStringEncryptor;
            return;
        }
        
        final TextEncryptor registeredTextEncryptor = registry.getTextEncryptor(this);
        if (registeredTextEncryptor != null) {
            this.textEncryptor = registeredTextEncryptor;
        }
        
    }


    
    private void writeObject(final ObjectOutputStream outputStream) throws IOException {
        
        final EncryptablePropertiesEncryptorRegistry registry =
                EncryptablePropertiesEncryptorRegistry.getInstance();
        if (this.textEncryptor != null) {
            registry.setTextEncryptor(this, this.textEncryptor);
        } else if (this.stringEncryptor != null) {
            registry.setStringEncryptor(this, this.stringEncryptor);
        }
        
        outputStream.defaultWriteObject();
        
    }

    /*
    Using this class allows for lazy decryption of properties. Especially projects that have many encrypted properties
    may suffer in performance if all properties are decrypted in one go. This solution allows for properties to only be
    decrypted on an if-needed basis.
     */
    private final class DecodedElementEnumeration implements Enumeration<Object> {

        private final Enumeration<Object> encodedEnumeration;

        public DecodedElementEnumeration(final Enumeration<Object> encodedEnumeration) {
            this.encodedEnumeration = encodedEnumeration;
        }

        @Override
        public boolean hasMoreElements() {
            return encodedEnumeration.hasMoreElements();
        }

        @Override
        public Object nextElement() {
            final Object encodedNextValue = encodedEnumeration.nextElement();
            // Returning null if the value is not a String is consistent with the other methods in this class.
            return encodedNextValue instanceof String ? decode((String) encodedNextValue) : null;
        }

    }

    /*
     * Because Properties.java does not support the add/addAll methods either, we mimic this behavior.
     * All entries in this set are lazily decoded. If a value is accessed once and decoded, it will remain decoded
     * for future references. This prevents duplicate decoding of a value.
     */
    private final class LazilyDecodedReadOnlyEntrySet extends HashSet<Map.Entry<Object, Object>> {

        public LazilyDecodedReadOnlyEntrySet(final int capacity) {
            super(capacity);
        }

        @Override
        public boolean add(final Map.Entry<Object, Object> e) {
            throw new UnsupportedOperationException();
        }

        @Override
        public boolean addAll(final Collection<? extends Map.Entry<Object, Object>> c) {
            throw new UnsupportedOperationException();
        }

        public void addEncoded(final Object key, final Object value) {
            super.add(new LazyDecodingEntry(key, value));
        }

        private final class LazyDecodingEntry implements Map.Entry<Object, Object> {

            private final Object key;
            private Object value;
            private boolean isDecoded = false;


            public LazyDecodingEntry(final Object key, final Object encodedValue) {
                this.key = key;
                this.value = encodedValue;
            }

            @Override
            public Object getKey() {
                return key;
            }

            @Override
            public synchronized Object getValue() {
                if (!isDecoded) {
                    value = value instanceof String ? decode((String) value) : null;
                    isDecoded = true;
                }
                return value;
            }

            @Override
            public synchronized Object setValue(final Object newValue) {
                final Object oldValue = this.value;
                this.value = newValue;
                return oldValue;
            }
        }

    }

    
}
