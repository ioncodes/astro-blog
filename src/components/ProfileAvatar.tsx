import { Avatar, AvatarFallback, AvatarImage } from "@/components/ui/avatar";

export default function ProfileAvatar() {
  return (
    <Avatar className="w-16 h-16">
      <AvatarImage src="/avatar.webp" />
      <AvatarFallback>CN</AvatarFallback>
    </Avatar>
  );
}