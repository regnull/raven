// Code generated by protoc-gen-go. DO NOT EDIT.
// source: signed_record.proto

package pbraven

import (
	fmt "fmt"
	proto "github.com/golang/protobuf/proto"
	math "math"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.ProtoPackageIsVersion3 // please upgrade the proto package

type SignedRecord struct {
	Record               *Record      `protobuf:"bytes,1,opt,name=record,proto3" json:"record,omitempty"`
	Signature            []*Signature `protobuf:"bytes,2,rep,name=signature,proto3" json:"signature,omitempty"`
	XXX_NoUnkeyedLiteral struct{}     `json:"-"`
	XXX_unrecognized     []byte       `json:"-"`
	XXX_sizecache        int32        `json:"-"`
}

func (m *SignedRecord) Reset()         { *m = SignedRecord{} }
func (m *SignedRecord) String() string { return proto.CompactTextString(m) }
func (*SignedRecord) ProtoMessage()    {}
func (*SignedRecord) Descriptor() ([]byte, []int) {
	return fileDescriptor_05cdeafd8fcb55af, []int{0}
}

func (m *SignedRecord) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_SignedRecord.Unmarshal(m, b)
}
func (m *SignedRecord) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_SignedRecord.Marshal(b, m, deterministic)
}
func (m *SignedRecord) XXX_Merge(src proto.Message) {
	xxx_messageInfo_SignedRecord.Merge(m, src)
}
func (m *SignedRecord) XXX_Size() int {
	return xxx_messageInfo_SignedRecord.Size(m)
}
func (m *SignedRecord) XXX_DiscardUnknown() {
	xxx_messageInfo_SignedRecord.DiscardUnknown(m)
}

var xxx_messageInfo_SignedRecord proto.InternalMessageInfo

func (m *SignedRecord) GetRecord() *Record {
	if m != nil {
		return m.Record
	}
	return nil
}

func (m *SignedRecord) GetSignature() []*Signature {
	if m != nil {
		return m.Signature
	}
	return nil
}

func init() {
	proto.RegisterType((*SignedRecord)(nil), "pbraven.SignedRecord")
}

func init() { proto.RegisterFile("signed_record.proto", fileDescriptor_05cdeafd8fcb55af) }

var fileDescriptor_05cdeafd8fcb55af = []byte{
	// 129 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0xe2, 0x12, 0x2e, 0xce, 0x4c, 0xcf,
	0x4b, 0x4d, 0x89, 0x2f, 0x4a, 0x4d, 0xce, 0x2f, 0x4a, 0xd1, 0x2b, 0x28, 0xca, 0x2f, 0xc9, 0x17,
	0x62, 0x2f, 0x48, 0x2a, 0x4a, 0x2c, 0x4b, 0xcd, 0x93, 0xe2, 0x41, 0x16, 0x96, 0xe2, 0x07, 0xa9,
	0x4d, 0x2c, 0x29, 0x2d, 0x4a, 0x85, 0x08, 0x28, 0x65, 0x72, 0xf1, 0x04, 0x83, 0xb5, 0x07, 0x81,
	0x95, 0x09, 0xa9, 0x73, 0xb1, 0x41, 0x34, 0x48, 0x30, 0x2a, 0x30, 0x6a, 0x70, 0x1b, 0xf1, 0xeb,
	0x41, 0x0d, 0xd2, 0x83, 0x28, 0x08, 0x82, 0x4a, 0x0b, 0x19, 0x70, 0x71, 0xc2, 0xcd, 0x92, 0x60,
	0x52, 0x60, 0xd6, 0xe0, 0x36, 0x12, 0x82, 0xab, 0x0d, 0x86, 0xc9, 0x04, 0x21, 0x14, 0x25, 0xb1,
	0x81, 0x6d, 0x34, 0x06, 0x04, 0x00, 0x00, 0xff, 0xff, 0xfe, 0x6a, 0x17, 0x6a, 0xb0, 0x00, 0x00,
	0x00,
}
