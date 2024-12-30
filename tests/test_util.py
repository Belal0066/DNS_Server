import unittest
import sys
import os

# Add the src directory to the Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../src')))

from utilDns import DnsMessage, parse_name, convertRaw_msg
from constsDns import DnsType, DnsClass

class TestDNSCompression(unittest.TestCase):

    def test_max_label_length(self):
        """Test that labels longer than 63 octets are rejected"""
        msg = DnsMessage()
        msg.id = 1234
        
        # Create a label that's too long (64 characters)
        long_label = 'a' * 64
        
        with self.assertRaises(ValueError):
            msg.question.append({
                'name': f'{long_label}.com.',
                'type': DnsType.A,
                'class': DnsClass.IN
            })
            msg.to_wire()

    def test_compression_pointer_loop_prevention(self):
        """Test that compression pointer loops are detected and prevented"""
        # Create a message with an invalid compression pointer that points to itself
        invalid_msg = bytearray([
            0x00, 0x01,  # ID
            0x00, 0x00,  # Flags
            0x00, 0x01,  # QDCOUNT
            0x00, 0x00,  # ANCOUNT
            0x00, 0x00,  # NSCOUNT
            0x00, 0x00,  # ARCOUNT
            0xC0, 0x0C,  # Compression pointer to offset 12 (itself)
        ])
        
        with self.assertRaises(ValueError):
            parse_name(invalid_msg, 12)

    def test_forward_pointer_prevention(self):
        """Test that forward compression pointers are rejected"""
        # Create a message with a compression pointer that points forward
        invalid_msg = bytearray([
            0x00, 0x01,  # ID
            0x00, 0x00,  # Flags
            0x00, 0x01,  # QDCOUNT
            0x00, 0x00,  # ANCOUNT
            0x00, 0x00,  # NSCOUNT
            0x00, 0x00,  # ARCOUNT
            0xC0, 0x20,  # Compression pointer to offset 32 (forward reference)
        ])
        
        with self.assertRaises(ValueError):
            parse_name(invalid_msg, 12)

    def test_message_truncation(self):
        """Test that messages are properly truncated when exceeding max size"""
        msg = DnsMessage()
        msg.id = 1234
        
        # Add a question
        msg.question.append({
            'name': 'example.com.',
            'type': DnsType.A,
            'class': DnsClass.IN
        })
        
        # Add many answers to force truncation
        for i in range(50):  # This should exceed 512 bytes
            msg.answer.append({
                'name': f'host{i}.example.com.',
                'type': DnsType.A,
                'class': DnsClass.IN,
                'ttl': 300,
                'rdata': f'192.0.2.{i % 255}'
            })
        
        # Convert to wire format with default UDP size limit
        wire = msg.to_wire()
        
        # Message should be truncated
        self.assertTrue(len(wire) <= DnsMessage.MAX_UDP_SIZE)
        
        # Parse the message back
        decoded = convertRaw_msg(wire)
        
        # Verify TC flag is set
        self.assertTrue(decoded.is_tc_set())
        
        # Question section should be complete
        self.assertEqual(len(decoded.question), 1)
        self.assertEqual(decoded.question[0]['name'], 'example.com.')

    def test_question_section_preservation(self):
        """Test that question section is always preserved even when truncating"""
        msg = DnsMessage()
        msg.id = 1234
        
        # Add a question with a very long name
        long_name = '.'.join(['section' + str(i) for i in range(30)]) + '.'
        msg.question.append({
            'name': long_name,
            'type': DnsType.A,
            'class': DnsClass.IN
        })
        
        # Add an answer
        msg.answer.append({
            'name': long_name,
            'type': DnsType.A,
            'class': DnsClass.IN,
            'ttl': 300,
            'rdata': '192.0.2.1'
        })
        
        # Convert to wire format with a small max_size
        wire = msg.to_wire(max_size=256)
        
        # Parse the message back
        decoded = convertRaw_msg(wire)
        
        # Verify the question section is complete
        self.assertEqual(len(decoded.question), 1)
        self.assertEqual(decoded.question[0]['name'], long_name)
        
        # Verify TC flag is set
        self.assertTrue(decoded.is_tc_set())

    def test_answer_boundary_truncation(self):
        """Test that truncation occurs at answer boundaries"""
        msg = DnsMessage()
        msg.id = 1234
        
        # Add a question
        msg.question.append({
            'name': 'example.com.',
            'type': DnsType.A,
            'class': DnsClass.IN
        })
        
        # Add several answers
        for i in range(5):
            msg.answer.append({
                'name': f'host{i}.example.com.',
                'type': DnsType.A,
                'class': DnsClass.IN,
                'ttl': 300,
                'rdata': f'192.0.2.{i}'
            })
        
        # Convert to wire format with a size limit that should allow only some answers
        wire = msg.to_wire(max_size=200)
        
        # Parse the message back
        decoded = convertRaw_msg(wire)
        
        # Verify that we have complete answers (no partial answers)
        for answer in decoded.answer:
            self.assertTrue('name' in answer)
            self.assertTrue('type' in answer)
            self.assertTrue('class' in answer)
            self.assertTrue('ttl' in answer)
            self.assertTrue('rdata' in answer)

    def test_tcp_message_format(self):
        """Test TCP message format with length prefix"""
        msg = DnsMessage()
        msg.id = 1234
        
        # Add a question
        msg.question.append({
            'name': 'example.com.',
            'type': DnsType.A,
            'class': DnsClass.IN
        })
        
        # Convert to TCP wire format
        tcp_wire = msg.to_tcp_wire()
        
        # First two bytes should be the length
        length = int.from_bytes(tcp_wire[0:2], 'big')
        self.assertEqual(length, len(tcp_wire) - 2)  # -2 for length field
        
        # Parse the TCP message back
        decoded = DnsMessage.from_tcp_wire(tcp_wire)
        self.assertEqual(decoded.id, 1234)
        self.assertEqual(decoded.question[0]['name'], 'example.com.')

    def test_tcp_large_message(self):
        """Test TCP handling of messages larger than UDP limit"""
        msg = DnsMessage()
        msg.id = 1234
        
        # Add a question
        msg.question.append({
            'name': 'example.com.',
            'type': DnsType.A,
            'class': DnsClass.IN
        })
        
        # Add many answers to exceed UDP limit
        for i in range(50):
            msg.answer.append({
                'name': f'host{i}.example.com.',
                'type': DnsType.A,
                'class': DnsClass.IN,
                'ttl': 300,
                'rdata': f'192.0.2.{i}'
            })
        
        # Convert to TCP wire format
        tcp_wire = msg.to_tcp_wire()
        
        # Message should be larger than UDP limit but within TCP limit
        self.assertTrue(len(tcp_wire) - 2 > DnsMessage.MAX_UDP_SIZE)
        self.assertTrue(len(tcp_wire) - 2 <= DnsMessage.MAX_TCP_SIZE)
        
        # Parse the TCP message back
        decoded = DnsMessage.from_tcp_wire(tcp_wire)
        self.assertEqual(len(decoded.answer), 50)
        self.assertFalse(decoded.is_tc_set())  # No truncation in TCP

    def test_tcp_max_size_limit(self):
        """Test that TCP messages respect maximum size limit"""
        msg = DnsMessage()
        msg.id = 1234
        
        # Add a question
        msg.question.append({
            'name': 'example.com.',
            'type': DnsType.A,
            'class': DnsClass.IN
        })
        
        # Try to create a message larger than MAX_TCP_SIZE
        # This is done by adding many long domain names
        long_names = []
        for i in range(1000):
            name = f"{'x' * 63}.{'y' * 63}.{'z' * 63}.example.com."
            long_names.append({
                'name': name,
                'type': DnsType.A,
                'class': DnsClass.IN,
                'ttl': 300,
                'rdata': '192.0.2.1'
            })
        msg.answer.extend(long_names)
        
        # Attempt to convert to TCP wire format should raise error
        with self.assertRaises(ValueError):
            msg.to_tcp_wire()

    def test_tcp_incomplete_message(self):
        """Test handling of incomplete TCP messages"""
        # Create a valid message first
        msg = DnsMessage()
        msg.id = 1234
        msg.question.append({
            'name': 'example.com.',
            'type': DnsType.A,
            'class': DnsClass.IN
        })
        tcp_wire = msg.to_tcp_wire()
        
        # Try to parse incomplete messages
        with self.assertRaises(ValueError):
            # Only length field
            DnsMessage.from_tcp_wire(tcp_wire[:2])
        
        with self.assertRaises(ValueError):
            # Length field + partial message
            DnsMessage.from_tcp_wire(tcp_wire[:10])

if __name__ == '__main__':
    unittest.main()
