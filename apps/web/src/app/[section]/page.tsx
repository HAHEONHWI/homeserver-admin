import { notFound } from "next/navigation";
import type { Metadata } from "next";
import { ResourcePage } from "@/components/resource-page";
import { findNavItem, resourceItems } from "@/lib/resources";

export function generateStaticParams() {
  return resourceItems.map(({ key }) => ({ section: key }));
}

export async function generateMetadata({ params }: { params: Promise<{ section: string }> }): Promise<Metadata> {
  const { section } = await params;
  const item = findNavItem(section);
  return item ? { title: item.label, description: item.subtitle } : {};
}

export default async function ResourceRoute({ params }: { params: Promise<{ section: string }> }) {
  const { section } = await params;
  if (!findNavItem(section) || section === "") notFound();
  return <ResourcePage resourceKey={section} />;
}
